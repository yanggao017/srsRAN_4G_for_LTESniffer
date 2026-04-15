/**
 * Copyright 2013-2023 Software Radio Systems Limited
 *
 * This file is part of srsRAN.
 *
 * srsRAN is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of
 * the License, or (at your option) any later version.
 *
 * srsRAN is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * A copy of the GNU Affero General Public License can be found in
 * the LICENSE file in the top-level directory of this distribution
 * and at http://www.gnu.org/licenses/.
 *
 */

#include "srsran/common/mac_pcap.h"
#include "srsran/common/string_helpers.h"
#include "srsran/common/test_common.h"
#include "srsran/config.h"
#include "srsran/mac/mac_rar_pdu_nr.h"
#include "srsran/mac/mac_sch_pdu_nr.h"

#include <array>
#include <algorithm>
#include <cctype>
#include <iostream>
#include <memory>
#include <vector>
#include <fstream>
#include "srsran/json.hpp"
#define PCAP 1
#define PCAP_CRNTI (0x1001)
#define PCAP_RAR_RNTI (0x0016)
#define PCAP_TTI (666)
 
using namespace srsran;

static std::unique_ptr<srsran::mac_pcap> pcap_handle = nullptr;
using json = nlohmann::json;

static std::string to_lower(std::string value)
{
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) { return std::tolower(c); });
    return value;
}

static uint32_t json_u32_or(const json& config, const char* key, uint32_t default_value)
{
    return config.contains(key) ? config[key].get<uint32_t>() : default_value;
}

static uint16_t json_u16_or(const json& config, const char* key, uint16_t default_value)
{
    return config.contains(key) ? static_cast<uint16_t>(config[key].get<uint32_t>()) : default_value;
}

static bool json_bool_or(const json& config, const char* key, bool default_value)
{
    return config.contains(key) ? config[key].get<bool>() : default_value;
}

static uint16_t default_rnti_for_type(const std::string& type)
{
    if (type == "ra" || type == "ra_rnti" || type == "rar") {
        return PCAP_RAR_RNTI;
    }
    if (type == "pch" || type == "pcch" || type == "p_rnti" || type == "paging") {
        return SRSRAN_PRNTI;
    }
    if (type == "si" || type == "si_rnti" || type == "bcch_dlsch" || type == "sib") {
        return SRSRAN_SIRNTI;
    }
    if (type == "mch" || type == "m_rnti" || type == "mbms") {
        return SRSRAN_MRNTI;
    }
    if (type == "bch" || type == "bcch_bch" || type == "mib") {
        return 0;
    }
    return PCAP_CRNTI;
}

// 将十六进制字符串转成字节数组
void hex_string_to_byte_array(const char *hex_string, uint8_t *byte_array)
{
    size_t len = strlen(hex_string);
    for (size_t i = 0; i < len; i += 2) {
        sscanf(hex_string + i, "%2hhx", &byte_array[i / 2]);
    }
}


// 根据 generation + direction 写入 PCAP
int write_mac_pdu(const std::string& generation,
                const std::string& direction,
                const std::string& type,
                const std::string& mac_hex,
                uint16_t           rnti,
                uint32_t           tti,
                uint8_t            cc_idx,
                bool               crc_ok)
{
    size_t mac_len = mac_hex.length() / 2;
    std::vector<uint8_t> mac_bytes(mac_len);
    hex_string_to_byte_array(mac_hex.c_str(), mac_bytes.data());

    if (!pcap_handle) {
        std::cerr << "pcap 句柄不存在！" << std::endl;
        return SRSRAN_ERROR;
    }

    // ====== NR 写法 ======
    if (generation == "nr") {
        if (direction == "dl") {
            if (type == "ra") {
                std::cout << "[INFO] 类型为 RA，写入 RA_RNTI\n";
                pcap_handle->write_dl_ra_rnti_nr(mac_bytes.data(), mac_len, rnti, 0, tti);
            } else if (type == "c_rnti") {
                std::cout << "[INFO] 类型为 C_RNTI，写入 CRNTI\n";
                pcap_handle->write_dl_crnti_nr(mac_bytes.data(), mac_len, rnti, 0, tti);
            } else if (type == "bch") {
                std::cout << "[INFO] 类型为 BCH，写入 BCH\n";
                pcap_handle->write_dl_bch_nr(mac_bytes.data(), mac_len, rnti, 0, tti);
            } else if (type == "pch") {
                std::cout << "[INFO] 类型为 PCH，写入 PCH\n";
                pcap_handle->write_dl_pch_nr(mac_bytes.data(), mac_len, rnti, 0, tti);
            } else if (type == "si_rnti") {
                std::cout << "[INFO] 类型为 SI_RNTI，写入 SI_RNTI\n";
                pcap_handle->write_dl_si_rnti_nr(mac_bytes.data(), mac_len, rnti, 0, tti);
            } else {
                std::cerr << "type 字段错误，应为 ra/c_rnti/bch/pch/si_rnti\n";
                return SRSRAN_ERROR;
            }

        } else if (direction == "ul") {
            std::cout << "[INFO] 使用 NR UL: write_ul_crnti_nr()\n";
            pcap_handle->write_ul_crnti_nr(mac_bytes.data(), mac_len, rnti, 0, tti);
        } else {
            std::cerr << "direction 字段错误，应为 ul/dl\n";
            return SRSRAN_ERROR;
        }
    }

    // ====== LTE 写法 ======
    else if (generation == "lte") {
        if (direction == "dl") {
            if (type == "c_rnti" || type == "crnti" || type == "dlsch" || type == "dl_sch") {
                std::cout << "[INFO] 使用 LTE DL-SCH/C-RNTI: write_dl_crnti()\n";
                pcap_handle->write_dl_crnti(mac_bytes.data(), mac_len, rnti, crc_ok, tti, cc_idx);
            } else if (type == "ra" || type == "ra_rnti" || type == "rar") {
                std::cout << "[INFO] 使用 LTE RA-RNTI/RAR: write_dl_ranti()\n";
                pcap_handle->write_dl_ranti(mac_bytes.data(), mac_len, rnti, crc_ok, tti, cc_idx);
            } else if (type == "bch" || type == "bcch_bch" || type == "mib") {
                std::cout << "[INFO] 使用 LTE BCH: write_dl_bch()\n";
                pcap_handle->write_dl_bch(mac_bytes.data(), mac_len, crc_ok, tti, cc_idx);
            } else if (type == "pch" || type == "pcch" || type == "p_rnti" || type == "paging") {
                std::cout << "[INFO] 使用 LTE PCH/P-RNTI: write_dl_pch()\n";
                pcap_handle->write_dl_pch(mac_bytes.data(), mac_len, crc_ok, tti, cc_idx);
            } else if (type == "si" || type == "si_rnti" || type == "bcch_dlsch" || type == "sib") {
                std::cout << "[INFO] 使用 LTE BCCH-DL-SCH/SI-RNTI: write_dl_sirnti()\n";
                pcap_handle->write_dl_sirnti(mac_bytes.data(), mac_len, crc_ok, tti, cc_idx);
            } else if (type == "mch" || type == "m_rnti" || type == "mbms") {
                std::cout << "[INFO] 使用 LTE MCH/M-RNTI: write_dl_mch()\n";
                pcap_handle->write_dl_mch(mac_bytes.data(), mac_len, crc_ok, tti, cc_idx);
            } else {
                std::cerr << "LTE DL type 字段错误，应为 c_rnti/dlsch/ra/bch/pch/si_rnti/mch\n";
                return SRSRAN_ERROR;
            }
        } else if (direction == "ul") {
            std::cout << "[INFO] 使用 LTE UL: write_ul_crnti()\n";
            pcap_handle->write_ul_crnti(mac_bytes.data(), mac_len, rnti, 1, tti, cc_idx);
        } else {
            std::cerr << "direction 字段错误，应为 ul/dl\n";
            return SRSRAN_ERROR;
        }
    }

    else {
        std::cerr << "generation 字段错误，应为 nr/lte\n";
        return SRSRAN_ERROR;
    }

    return SRSRAN_SUCCESS;
}


int main(int argc, char** argv)
{
    if (argc < 2) {
        std::cerr << "请提供 JSON 配置文件路径，例如： ./mac_writer config.json\n";
        return -1;
    }

    // 读取 JSON 文件
    std::ifstream config_file(argv[1]);
    if (!config_file.is_open()) {
        std::cerr << "无法打开 JSON 文件！\n";
        return -1;
    }

    json config;
    config_file >> config;
    config_file.close();

    std::string generation = to_lower(config.value("generation", "lte"));
    std::string direction = to_lower(config.value("direction", "dl"));
    std::string mac_hex = config.contains("mac_hex") ? config["mac_hex"].get<std::string>() : config["max_hex"].get<std::string>();
    std::string type = to_lower(config.value("type", direction == "dl" ? "c_rnti" : "c_rnti"));
    uint16_t rnti = json_u16_or(config, "rnti", default_rnti_for_type(type));
    uint32_t tti = json_u32_or(config, "tti", PCAP_TTI);
    uint8_t cc_idx = static_cast<uint8_t>(json_u32_or(config, "cc_idx", 1));
    bool crc_ok = json_bool_or(config, "crc_ok", true);

    std::cout << "加载 JSON 配置:\n";
    std::cout << "  generation = " << generation << "\n";
    std::cout << "  direction  = " << direction << "\n";
    std::cout << "  type       = " << type << "\n";
    std::cout << "  rnti       = 0x" << std::hex << rnti << std::dec << "\n";
    std::cout << "  tti        = " << tti << "\n";
    std::cout << "  cc_idx     = " << static_cast<uint32_t>(cc_idx) << "\n";
    std::cout << "  crc_ok     = " << (crc_ok ? "true" : "false") << "\n";
    std::cout << "  mac_hex    = " << mac_hex << "\n";


    // 打开 PCAP 文件
    pcap_handle = std::unique_ptr<mac_pcap>(new mac_pcap());
    pcap_handle->open("output_mac_pdu.pcap");

    // 写入
    if (write_mac_pdu(generation, direction, type, mac_hex, rnti, tti, cc_idx, crc_ok)) {
        std::cerr << "写入 MAC PDU 失败！\n";
        return SRSRAN_ERROR;
    }

    // 关闭
    pcap_handle->close();
    std::cout << "写入完成，输出文件：output_mac_pdu.pcap\n";

    return SRSRAN_SUCCESS;
}
