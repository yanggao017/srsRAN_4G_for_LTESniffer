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
                const std::string& mac_hex)
{
    size_t mac_len = mac_hex.length() / 2;
    uint8_t mac_bytes[mac_len];
    hex_string_to_byte_array(mac_hex.c_str(), mac_bytes);

    if (!pcap_handle) {
        std::cerr << "pcap 句柄不存在！" << std::endl;
        return SRSRAN_ERROR;
    }

    // ====== NR 写法 ======
    if (generation == "nr") {
        if (direction == "dl") {
            std::cout << "[INFO] 使用 NR DL: write_dl_crnti_nr()\n";
            pcap_handle->write_dl_crnti_nr(mac_bytes, mac_len, PCAP_CRNTI, true, PCAP_TTI);
        } else if (direction == "ul") {
            std::cout << "[INFO] 使用 NR UL: write_ul_crnti_nr()\n";
            pcap_handle->write_ul_crnti_nr(mac_bytes, mac_len, PCAP_CRNTI, true, PCAP_TTI);
        } else {
            std::cerr << "direction 字段错误，应为 ul/dl\n";
            return SRSRAN_ERROR;
        }
    }

    // ====== LTE 写法 ======
    else if (generation == "lte") {
        if (direction == "dl") {
            std::cout << "[INFO] 使用 LTE DL: write_dl_crnti()\n";
            pcap_handle->write_dl_crnti(mac_bytes, mac_len, PCAP_CRNTI, 1, true, PCAP_TTI, 1);
        } else if (direction == "ul") {
            std::cout << "[INFO] 使用 LTE UL: write_ul_crnti()\n";
            pcap_handle->write_ul_crnti(mac_bytes, mac_len, PCAP_CRNTI, true, PCAP_TTI);
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

    std::string generation = config["generation"];
    std::string direction = config["direction"];
    std::string mac_hex = config["max_hex"];

    std::cout << "加载 JSON 配置:\n";
    std::cout << "  generation = " << generation << "\n";
    std::cout << "  direction  = " << direction << "\n";
    std::cout << "  mac_hex    = " << mac_hex << "\n";


    // 打开 PCAP 文件
    pcap_handle = std::unique_ptr<mac_pcap>(new mac_pcap());
    pcap_handle->open("output_mac_pdu.pcap");

    // 写入
    if (write_mac_pdu(generation, direction, mac_hex)) {
        std::cerr << "写入 MAC PDU 失败！\n";
        return SRSRAN_ERROR;
    }

    // 关闭
    pcap_handle->close();
    std::cout << "写入完成，输出文件：output_mac_pdu.pcap\n";

    return SRSRAN_SUCCESS;
}
