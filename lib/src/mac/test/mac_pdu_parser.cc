#include "srsran/common/common.h"
#include "srsran/common/interfaces_common.h"
#include "srsran/common/mac_pcap.h"
#include "srsran/common/test_common.h"
#include "srsran/mac/pdu.h"
#include "srsran/rlc/rlc_am_base.h"
#include "srsran/rlc/rlc_common.h"
#include "srsran/rlc/rlc_am_lte.h"
#include "srsran/asn1/liblte_mme.h"
#include "srsran/asn1/rrc.h"
#include "srsran/asn1/rrc/ul_dcch_msg.h"

extern "C" {
#include "srsran/phy/phch/dci.h"
}

#include <bitset>
#include <iostream>
#include <map>
#include <random>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include "srsran/json.hpp" // JSON 库 https://github.com/nlohmann/json

using json = nlohmann::ordered_json;
using namespace srsran;
using namespace asn1;
using namespace asn1::rrc;
#define HAVE_PCAP 0
std::random_device rd;
std::mt19937 rand_gen(rd());
std::uniform_int_distribution<uint8_t> uniform_dist_u8(0, 255);

static std::unique_ptr<mac_pcap> pcap_handle = nullptr;
static void parse_ul_dcch(uint32_t lcid, srsran::unique_byte_buffer_t pdu);
static void handle_rrc_con_setup_complete(rrc_conn_setup_complete_s* msg, srsran::unique_byte_buffer_t pdu);
static bool handle_attach_request(srsran::byte_buffer_t* nas_rx);
static std::vector<std::string> split_on_blank_lines(const std::string& s);
json parse_pdcp_pdu(uint8_t* sdu_ptr, uint32_t payload_len, uint32_t lcid, std::vector<uint8_t>* raw_bytes=nullptr);
json parse_rlc_pdu(uint8_t* sdu_ptr, uint32_t payload_length, uint32_t lcid, std::vector<uint8_t>* raw_bytes=nullptr);
json parse_mac_subh(srsran::sch_subh* subh, size_t id, std::vector<uint8_t>* rlc_raw=nullptr);
json parse_mac_pdu(uint8_t* mac_pdu, size_t length, std::vector<std::vector<uint8_t>>* rlc_raw_list=nullptr);
std::vector<std::vector<uint8_t>> all_rlc_pdus; // 用于存储所有拼接的 RLC PDU
// RLC SDU 重组状态
struct rlc_sdu_reassembler {
    uint32_t lcid;
    uint32_t next_expected_sn = 0;
    bool     waiting_for_first = true;
    std::map<uint32_t, std::vector<uint8_t>> fragments; // SN -> fragment
    std::vector<uint8_t> reassembled_sdu;

    void reset() {
        fragments.clear();
        reassembled_sdu.clear();
        waiting_for_first = true;
        next_expected_sn = 0;
    }

    // 添加一个 RLC AMD PDU 数据段
    bool add_fragment(uint32_t sn, const uint8_t* data, uint32_t len, bool is_first, bool is_last) {
        printf("sn:%d is_first:%d is_last:%d next_expected_sn:%d\n", sn, is_first, is_last, next_expected_sn);
        if (is_first) {
            reset(); // 开始新 SDU
            next_expected_sn = sn;
            waiting_for_first = false;
        }

        if (waiting_for_first) {
            printf("RLC Reassembly: Ignoring fragment until first is received (SN=%u)\n", sn);
            return false;
        }

        if (sn != next_expected_sn) {
            printf("RLC Reassembly: Gap detected! Expected SN=%u, got SN=%u. Resetting.\n", next_expected_sn, sn);
            reset();
            return false;
        }

        // 存储片段
        fragments[sn] = std::vector<uint8_t>(data, data + len);
        next_expected_sn = (sn + 1) % 4096; // RLC AM SN 12-bit

        if (is_last) {
            // 拼接所有片段
            reassembled_sdu.clear();
            for (auto& f : fragments) {
                reassembled_sdu.insert(reassembled_sdu.end(), f.second.begin(), f.second.end());
            }
            printf("RLC Reassembly: Had reassembled\n");
            return true; // 完整 SDU 已重组

        }

        return false; // 继续等待
    }
};
// 全局 RLC 重组器，key = lcid
std::map<uint32_t, rlc_sdu_reassembler> rlc_reassemblers;
#define TEST_CRNTI (0x1001)

// ---------------------- 辅助函数 ----------------------
// 将十六进制字符串转换成字节数组
void hex_string_to_byte_array(const char* hex_string, uint8_t* byte_array)
{
    size_t len = strlen(hex_string);
    for (size_t i = 0; i < len; i += 2)
        sscanf(hex_string + i, "%2hhx", &byte_array[i / 2]);
}

// 打印十六进制内容，用于调试
void hexdump(uint8_t* data, size_t length)
{
    for (size_t i = 0; i < length; i += 16)
    {
        printf("%08zx: ", i);
        for (size_t j = 0; j < 16 && (i + j) < length; ++j)
            printf("%02X ", data[i + j]);
        printf("\n");
    }
    printf("\n");
}

// 计算帧序列号（SN）
uint32_t SN(uint32_t count, uint32_t sn_len)
{
    return count & (0xFFFFFFFF >> (32 - sn_len));
}

// 将 2 个字节转换为一个 16 位无符号整数
void uint8_to_uint16(uint8_t* buf, uint16_t* i)
{
    *i = (uint32_t)buf[0] << 8 | (uint32_t)buf[1];
}

// 将 3 个字节转换为一个 24 位无符号整数
void uint8_to_uint24(uint8_t* buf, uint32_t* i)
{
    *i = (uint32_t)buf[0] << 16 | (uint32_t)buf[1] << 8 | (uint32_t)buf[2];
}

// ---------------------- PDCP SN 读取函数 ----------------------
uint32_t read_pdcp_sn(const unique_byte_buffer_t& pdcp_pdu, uint32_t sn_len)
{
    uint32_t sn = 0;
    for (uint32_t i = 0; i < (sn_len + 7) / 8; i++)
    {
        sn <<= 8;
        sn |= pdcp_pdu->msg[i];
    }
    if (sn_len % 8 != 0)
        sn >>= (8 - (sn_len % 8));
    return sn;
}

// ---------------------- PDCP 层解析 ---------------------- 
uint32_t read_data_header(const unique_byte_buffer_t& pdu, uint32_t sn_len)
{
    uint16_t rcvd_sn_16 = 0;
    uint32_t rcvd_sn_32 = 0;
    switch (sn_len)
    {
    case PDCP_SN_LEN_5:
        rcvd_sn_32 = SN(pdu->msg[0], sn_len);  // Short SN
        break;
    case PDCP_SN_LEN_7:
        rcvd_sn_32 = SN(pdu->msg[0], sn_len);  // 7-bit SN (if applicable)
        break;
    case PDCP_SN_LEN_12:
        uint8_to_uint16(pdu->msg, &rcvd_sn_16);  // 16-bit SN
        rcvd_sn_32 = SN(rcvd_sn_16, sn_len);
        break;
    case PDCP_SN_LEN_18:
        uint8_to_uint24(pdu->msg, &rcvd_sn_32);  // 24-bit SN
        rcvd_sn_32 = SN(rcvd_sn_32, sn_len);
        break;
    default:
        printf("Cannot extract RCVD_SN, invalid SN length configured: %d\n", sn_len);
    }

    return rcvd_sn_32;
}

int main(int argc, char** argv) {
    std::vector<std::string> input_files;
    std::vector<json> mac_json_list;

    // ---------- 解析命令行参数 ----------
    for (int i = 1; i < argc; ++i) {
        if (std::string(argv[i]) == "-i" && i + 1 < argc) {
            for (int j = i + 1; j < argc && input_files.size() < 5; ++j) {
                input_files.push_back(argv[j]);
            }
            break;
        }
    }

    if (!input_files.empty()) {
        for (const auto& input_file : input_files) {
            std::ifstream ifs(input_file);
            if (!ifs.is_open()) {
                printf("\033[1;31m[x] 无法打开文件: %s\033[0m\n", input_file.c_str());
                continue; // 如果无法打开文件，跳过该文件
            }

            std::string hex_input((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());
            ifs.close();
            hex_input.erase(std::remove_if(hex_input.begin(), hex_input.end(),
                                        [](unsigned char c) { return std::isspace(c); }),
                            hex_input.end());

            size_t byte_array_length = hex_input.size() / 2;
            uint8_t* mac_pdu = new uint8_t[byte_array_length];
            hex_string_to_byte_array(hex_input.c_str(), mac_pdu);

            //rlc_reassemblers.clear();
            std::vector<std::vector<uint8_t>> rlc_list;
            json mac_json = parse_mac_pdu(mac_pdu, byte_array_length, &rlc_list);

            mac_json_list.push_back(mac_json);
            delete[] mac_pdu;
        }
        return 0;
    }
    int choice;
    printf("\033[1;36m"); 
    printf("#####################################################################################################################\n");
    printf("#                                                                                                                   #\n");
    printf("# ███╗   ███╗ █████╗  ██████╗       ██████╗ ██████╗ ██╗   ██╗      ██████╗  █████╗ ██████╗ ███████╗███████╗██████╗  #\n");
    printf("# ████╗ ████║██╔══██╗██╔════╝       ██╔══██╗██╔══██╗██║   ██║      ██╔══██╗██╔══██╗██╔══██╗██╔════╝██╔════╝██╔══██╗ #\n");
    printf("# ██╔████╔██║███████║██║     █████╗ ██████╔╝██║  ██║██║   ██║█████╗██████╔╝███████║██████╔╝███████╗█████╗  ██████╔╝ #\n");
    printf("# ██║╚██╔╝██║██╔══██║██║     ╚════╝ ██╔═══╝ ██║  ██║██║   ██║╚════╝██╔═══╝ ██╔══██║██╔══██╗╚════██║██╔══╝  ██╔══██╗ #\n");
    printf("# ██║ ╚═╝ ██║██║  ██║╚██████╗       ██║     ██████╔╝╚██████╔╝      ██║     ██║  ██║██║  ██║███████║███████╗██║  ██║ #\n");
    printf("# ╚═╝     ╚═╝╚═╝  ╚═╝ ╚═════╝       ╚═╝     ╚═════╝  ╚═════╝       ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚══════╝╚═╝  ╚═╝ #\n");
    printf("#                                                                                                                   #\n");
    printf("#####################################################################################################################\n");
    printf("[+] 请选择解析方式:\n");
    printf("[+] 1. 手动输入 HEX 数据\n");
    printf("[+] 2. 使用 Tshark 提取 HEX 数据\n");
    printf("[+] 请输入选项 (1 或 2):");
    printf("\033[0m");

    if (scanf("%d", &choice) != 1) {
        printf("\033[1;31m[x] 输入无效，请输入数字\033[0m\n");
        return 1; // 处理输入错误
    }
    if (choice == 1) {
        printf("\033[1;36m[+] 请输入 HEX Stream: \033[0m\n");
        std::string hex_input;
        std::cin.ignore(); // 清除输入缓冲区
        std::getline(std::cin, hex_input);

        // 将输入的十六进制字符串转换为字节数组
        size_t byte_array_length = hex_input.size() / 2;
        uint8_t* mac_pdu = new uint8_t[byte_array_length];
        hex_string_to_byte_array(hex_input.c_str(), mac_pdu);

        // JSON 解析
        json mac_json = parse_mac_pdu(mac_pdu, byte_array_length);
        printf("%s\n",mac_json.dump(4).c_str());
        if(!mac_json.empty()) {
            // 保存 JSON 文件
            std::ofstream ofs("/home/ubuntu/workarea/srsRAN_4G_rlc/lib/src/mac/test/output/manual_input.json");
            ofs << std::setw(4) << mac_json << std::endl;
            ofs.close();
            printf("\033[1;32m[+] 数据解析成功, 已保存至 /home/ubuntu/workarea/srsRAN_4G_rlc/lib/src/mac/test/output/manual_input.json\033[0m\n");
        }else{
            printf("\033[1;31m[x] 数据解析失败, 可能是空数据或格式错误\033[0m\n");
        }
        delete[] mac_pdu;
        return 0;
    }
    else if (choice == 2) {
        // 执行 tshark 和 sed 命令，导出 hex.txt
        std::cout << "[+] 正在使用 Tshark 导出 hex.txt 文件...\n";
        std::string command = R"(tshark -r /home/ubuntu/workarea/srsRAN_4G_rlc/lib/src/mac/test/input/test.pcap -x | sed -E 's/^[0-9a-f]{4}\s+//; s/\s{2,}.*$//' > /home/ubuntu/workarea/srsRAN_4G_rlc/lib/src/mac/test/input/hex.txt)";
        int ret = std::system(command.c_str());

        if (ret != 0) {
            std::cerr << "[+] 执行命令失败，无法生成 hex.txt 文件\n";
            return 1;
        }

        printf("[+] hex.txt 导出成功, 开始解析 MAC-PDU ...\n");
        const char* filepath = "/home/ubuntu/workarea/srsRAN_4G_rlc/lib/src/mac/test/input/hex.txt";
        printf("[+] 开始读取十六进制数据 %s\n", filepath);
        std::ifstream file(filepath, std::ios::binary);
        if (!file) {
            std::cerr << "[x] 无法打开文件 hex.txt\n";
            return 1;
        }

        std::ostringstream buffer;
        buffer << file.rdbuf();
        std::string hex_str = buffer.str();
        file.close();

        printf("[+] 十六进制读取成功，开始分割数据包\n");
        std::vector<std::string> blocks = split_on_blank_lines(hex_str);

        printf("[+] 数据分割成功，共分割出 %zu 个数据包\n", blocks.size());
        for (size_t idx = 0; idx < blocks.size(); ++idx) {
        // for (size_t idx = 0; idx < 10; ++idx) { // 调试用
            if (blocks[idx].size() > 68) {
                blocks[idx] = blocks[idx].substr(68);  // 从第35字节开始
            }

            // printf("===================== 数据包 %zu =====================\n", idx);
            // printf("%s\n\n", blocks[idx].c_str());

            std::string block = blocks[idx];
            size_t byte_array_length = block.size() / 2;
            uint8_t* mac_pdu = new uint8_t[byte_array_length];
            hex_string_to_byte_array(block.c_str(), mac_pdu);

            // JSON 解析
            json mac_json = parse_mac_pdu(mac_pdu, byte_array_length);
            // printf("%s\n",mac_json.dump(4).c_str());
            if(!mac_json.empty()) {
                // 保存 JSON 文件
                std::ofstream ofs("/home/ubuntu/workarea/srsRAN_4G_rlc/lib/src/mac/test/output/" + std::to_string(idx) + ".json");
                ofs << std::setw(4) << mac_json << std::endl;
                ofs.close();
                printf("\033[1;32m[+] 数据块 %zu 解析成功, 已保存至 /home/ubuntu/workarea/srsRAN_4G_rlc/lib/src/mac/test/output/%zu.json\n\033[0m", idx, idx);
            }else{
                printf("\033[1;31m[x] 数据块 %zu 解析失败, 可能是空数据或格式错误\n\033[0m", idx);
            }
            delete[] mac_pdu;
        }
    } else{
        printf("\033[1;31m[x] 无效的选项，请输入 1 或 2\033[0m\n");
    }
    return 0;
}
json parse_pdcp_pdu(uint8_t* sdu_ptr, uint32_t payload_len, uint32_t lcid, std::vector<uint8_t>* raw_bytes)
{
    json pdcp_json;

    if(raw_bytes) raw_bytes->assign(sdu_ptr, sdu_ptr+payload_len);

    // 原有逻辑保持不变
    unique_byte_buffer_t pdcp_pdu = srsran::make_byte_buffer();
    pdcp_pdu->N_bytes = payload_len;
    memcpy(pdcp_pdu->msg, sdu_ptr, payload_len);

    uint32_t pdcp_sn = 0;
    uint32_t sn_len = (lcid <= 2) ? PDCP_SN_LEN_5 : PDCP_SN_LEN_12;
    pdcp_sn = read_data_header(pdcp_pdu, sn_len);

    uint32_t hdr_len_bytes = (uint32_t)ceilf((float)sn_len / 8.0f);
    const uint32_t mac_len = 4;
    uint32_t rrc_payload_len = (payload_len > hdr_len_bytes + mac_len) ? payload_len - hdr_len_bytes - mac_len : 0;
    uint8_t* rrc_ptr = sdu_ptr + hdr_len_bytes;

    pdcp_json["pdcp_sn"] = pdcp_sn;
    pdcp_json["payload_len"] = payload_len;

    std::ostringstream oss_full;
    for(uint32_t i=0;i<payload_len;i++) oss_full << std::hex << std::setw(2) << std::setfill('0') << (int)sdu_ptr[i];
    pdcp_json["payload_hex"] = oss_full.str();

    json rrc_json;
    rrc_json["rrc_payload_len"] = rrc_payload_len;
    std::ostringstream oss_rrc;
    for(uint32_t i=0;i<rrc_payload_len;i++) oss_rrc << std::hex << std::setw(2) << std::setfill('0') << (int)rrc_ptr[i];
    rrc_json["rrc_payload_hex"] = oss_rrc.str();

    // ✅ 打印当前 pdcp_json（包含 RRC hex）
    std::cout << "=== PDCP PDU 解析结果 ===" << std::endl;
    std::cout << pdcp_json.dump(4) << std::endl;  // 格式化输出，缩进 4 格

    // ✅ 打印 rrc_json 单独内容
    std::cout << "=== RRC 载荷信息 ===" << std::endl;
    std::cout << rrc_json.dump(4) << std::endl;

    if(rrc_payload_len>0) {
        srsran::unique_byte_buffer_t rrc_pdu = srsran::make_byte_buffer();
        rrc_pdu->N_bytes = rrc_payload_len;
        memcpy(rrc_pdu->msg, rrc_ptr, rrc_payload_len);
        parse_ul_dcch(lcid, std::move(rrc_pdu));
    }

    return pdcp_json;
}
json parse_rlc_pdu(uint8_t* sdu_ptr, uint32_t payload_length, uint32_t lcid, std::vector<uint8_t>* raw_bytes)
{
    json rlc_json;

    if(rlc_am_is_control_pdu(sdu_ptr)) {
        rlc_json["dc"] = "Control PDU";
        // 控制 PDU 不参与重组，直接返回
        return rlc_json;
    }

    rlc_amd_pdu_header_t header = {};
    uint32_t payload_len = payload_length;
    uint8_t* payload_data = sdu_ptr;

    // 解析 RLC AMD PDU 头
    rlc_am_read_data_pdu_header(&payload_data, &payload_len, &header);


    rlc_json["dc"] = "Data PDU";
    rlc_json["sn"] = header.sn;
    rlc_json["rf"] = header.rf;
    rlc_json["p"]  = header.p;
    rlc_json["fi"] = header.fi;
    rlc_json["lsf"] = header.lsf;
    rlc_json["so"] = header.so;
    rlc_json["N_li"] = header.N_li;

    std::vector<uint32_t> li_vec;
    for(uint32_t i = 0; i < header.N_li; i++) {
        li_vec.push_back(header.li[i]);
    }
    rlc_json["li"] = li_vec;

    // --- RLC 重组逻辑 ---
    auto& reassembler = rlc_reassemblers[lcid];
    reassembler.lcid = lcid;

    // --- ✅ 根据你定义的 FI 语义，解析 is_first / is_last ---
    bool is_first = false;
    bool is_last  = false;

    switch (header.fi) {
        case 0x0: // FI = 00: 完整的 RLC SDU
            is_first = true;
            is_last  = true;
            break;

        case 0x1: // FI = 01: 起始或中间分片（非最后）
            is_first = true;  // ✅ 视为起始片段，触发 reset()
            is_last  = false; // 尚未结束
            break;

        case 0x2: // FI = 10: 最后一个分片
            is_first = false; // 不是起始
            is_last  = true;  // 是最后一个，触发重组
            break;

        default:
            // FI = 0x3 或其他：未定义
            printf("RLC PDU: Unknown FI value 0x%x, treating as middle fragment\n", header.fi);
            is_first = false;
            is_last  = false;
            break;
    }
    printf("RLC PDU: LCID=%u, SN=%u, FI=0x%x (F=%d,L=%d), SO=%u, PayloadLen=%u\n",
        lcid, header.sn, header.fi,
        is_first,
        is_last,
        header.so, payload_len);
    bool complete_sdu = reassembler.add_fragment(
        header.sn,
        payload_data,
        payload_len,
        is_first,
        is_last
    );

    if (complete_sdu) {
        // ✅ 完整 RLC SDU 已重组，传递给 PDCP
        printf("RLC Reassembly: Successfully reassembled SDU for LCID=%u, total length=%zu\n",
               lcid, reassembler.reassembled_sdu.size());

        if (raw_bytes) {
            raw_bytes->assign(reassembler.reassembled_sdu.begin(), reassembler.reassembled_sdu.end());
        }

        // 解析完整 PDCP PDU
        json pdcp_json = parse_pdcp_pdu(
            reassembler.reassembled_sdu.data(),
            reassembler.reassembled_sdu.size(),
            lcid,
            raw_bytes
        );
        rlc_json["pdcp_pdu"] = pdcp_json;
    } else {
        // 仍在等待更多片段
        rlc_json["status"] = "fragment";
        if (is_first) rlc_json["fragment"] = "first";
        if (is_last)  rlc_json["fragment"] = "last";
        if (!is_first && !is_last) rlc_json["fragment"] = "middle";
    }

    return rlc_json;
}
json parse_mac_subh(srsran::sch_subh* subh, size_t id, std::vector<uint8_t>* rlc_raw)
{
    json subh_json = json::object();
    subh_json["subheader_id"] = id;

    if(subh->is_sdu()) {
        uint8_t* sdu_ptr = subh->get_sdu_ptr();
        int payload_len = subh->get_payload_size();
        uint32_t lcid = subh->get_sdu_lcid();

        subh_json["type"] = "MAC-SDU";
        subh_json["lcid"] = lcid;
        subh_json["payload_length"] = payload_len;
        subh_json["rlc_pdu"] = parse_rlc_pdu(sdu_ptr, payload_len, lcid, rlc_raw);
    } else {
        subh_json["type"] = "MAC-CE";
        auto ce_type = subh->ul_sch_ce_type();
        subh_json["ce_type"] = srsran::to_string(ce_type);

        json ce_details;
        if(ce_type==ul_sch_lcid::LONG_BSR || ce_type==ul_sch_lcid::SHORT_BSR || ce_type==ul_sch_lcid::TRUNC_BSR){
            uint32_t bsr_idx[4]={0}, bsr_bytes[4]={0};
            subh->get_bsr(bsr_idx, bsr_bytes);
            for(int i=0;i<4;i++) if(bsr_idx[i]>0) ce_details["LCG"+std::to_string(i)] = bsr_bytes[i];
        } else if(ce_type==ul_sch_lcid::PHR_REPORT){
            ce_details["PHR_dB"] = subh->get_phr();
        } else if(ce_type==ul_sch_lcid::CRNTI){
            ce_details["C-RNTI"] = subh->get_c_rnti();
        } else if(ce_type==ul_sch_lcid::PADDING){
            ce_details["padding_bytes"] = subh->get_payload_size();
        }
        subh_json["details"] = ce_details;
    }

    return subh_json;
}
json parse_mac_pdu(uint8_t* mac_pdu, size_t length, std::vector<std::vector<uint8_t>>* rlc_raw_list)
{
    sch_pdu pdu(20, srslog::fetch_basic_logger("MAC"));
    pdu.init_rx(length, true);
    pdu.parse_packet(mac_pdu);

    json mac_json;
    mac_json["subheader_count"] = pdu.nof_subh();
    mac_json["subheaders"] = json::array();

    size_t idx = 0;
    while(pdu.next()){
        sch_subh* subh = pdu.get();
        std::vector<uint8_t> rlc_bytes;
        mac_json["subheaders"].push_back(parse_mac_subh(subh, idx++, &rlc_bytes));
        if(rlc_raw_list && !rlc_bytes.empty()) rlc_raw_list->push_back(rlc_bytes);
    }

    return mac_json;
}

static void parse_ul_dcch(uint32_t lcid, srsran::unique_byte_buffer_t pdu)
{
  ul_dcch_msg_s  ul_dcch_msg;
  asn1::cbit_ref bref(pdu->msg, pdu->N_bytes);
  if (ul_dcch_msg.unpack(bref) != asn1::SRSASN_SUCCESS or
      ul_dcch_msg.msg.type().value != ul_dcch_msg_type_c::types_opts::c1) {
    printf("Failed to unpack UL-DCCH message\n");
    return;
  }

  pdu = srsran::make_byte_buffer();
  if (pdu == nullptr) {
    printf("Couldn't allocate PDU.");
  }

  int transaction_id = 0;

  switch (ul_dcch_msg.msg.c1().type()) {
    case ul_dcch_msg_type_c::c1_c_::types::rrc_conn_setup_complete:
      printf("test yg it's a rrc_conn_setup_complete\n");
      handle_rrc_con_setup_complete(&ul_dcch_msg.msg.c1().rrc_conn_setup_complete(), std::move(pdu));
      break;
    case ul_dcch_msg_type_c::c1_c_::types::rrc_conn_reest_complete:
      printf("test yg it's a rrc_conn_reest_complete\n");
      break;
    case ul_dcch_msg_type_c::c1_c_::types::ul_info_transfer:
      printf("test yg it's a ul_info_transfer\n");
      break;
    case ul_dcch_msg_type_c::c1_c_::types::rrc_conn_recfg_complete:
      printf("test yg it's a rrc_conn_recfg_complete\n");
      break;
    case ul_dcch_msg_type_c::c1_c_::types::security_mode_complete:
      printf("test yg it's a security_mode_complete\n");
      break;
    case ul_dcch_msg_type_c::c1_c_::types::security_mode_fail:
      printf("test yg it's a security_mode_fail\n");
      break;
    case ul_dcch_msg_type_c::c1_c_::types::ue_cap_info:
      printf("test yg it's a ue_cap_info\n");
      break;
    case ul_dcch_msg_type_c::c1_c_::types::meas_report:
      printf("test yg it's a meas_report\n");
      break;
    case ul_dcch_msg_type_c::c1_c_::types::ue_info_resp_r9:
      printf("test yg it's a ue_info_resp_r9\n");
      break;
    default:
      printf("Msg: %s not supported", ul_dcch_msg.msg.c1().type().to_string());
      break;
  }
}

static void handle_rrc_con_setup_complete(rrc_conn_setup_complete_s* msg, srsran::unique_byte_buffer_t pdu)
{
    asn1::json_writer json_writer;
    msg->to_json(json_writer);
    std::string json_str = json_writer.to_string();
    srsran::console("%s\n", json_str.c_str());
    rrc_conn_setup_complete_r8_ies_s* msg_r8 = &msg->crit_exts.c1().rrc_conn_setup_complete_r8();
    pdu->N_bytes = msg_r8->ded_info_nas.size();
    memcpy(pdu->msg, msg_r8->ded_info_nas.data(), pdu->N_bytes);

    uint8_t pd, msg_type, sec_hdr_type;


    liblte_mme_parse_msg_sec_header((LIBLTE_BYTE_MSG_STRUCT*)pdu.get(), &pd, &sec_hdr_type);
    srsran::console("Initial UE message sec header: %s\n", liblte_nas_sec_hdr_type_to_string(sec_hdr_type));

        // Check MAC if message is integrity protected
    if (sec_hdr_type == LIBLTE_MME_SECURITY_HDR_TYPE_INTEGRITY ||
        sec_hdr_type == LIBLTE_MME_SECURITY_HDR_TYPE_INTEGRITY_WITH_NEW_EPS_SECURITY_CONTEXT ||
        sec_hdr_type == LIBLTE_MME_SECURITY_HDR_TYPE_INTEGRITY_AND_CIPHERED ||
        sec_hdr_type == LIBLTE_MME_SECURITY_HDR_TYPE_INTEGRITY_AND_CIPHERED_WITH_NEW_EPS_SECURITY_CONTEXT) {
            srsran::console("NAS INTEGRITY Protected\n");
    }
    // Decrypt message if indicated
    if (sec_hdr_type == LIBLTE_MME_SECURITY_HDR_TYPE_INTEGRITY_AND_CIPHERED ||
        sec_hdr_type == LIBLTE_MME_SECURITY_HDR_TYPE_INTEGRITY_AND_CIPHERED_WITH_NEW_EPS_SECURITY_CONTEXT) {
            srsran::console("NAS INTEGRITY AND CIPHERED Protected\n");
    }

    liblte_mme_parse_msg_header((LIBLTE_BYTE_MSG_STRUCT*)pdu.get(), &pd, &msg_type);
    srsran::console("Initial UE message: %s\n", liblte_nas_msg_type_to_string(msg_type));

    switch (msg_type) {
        case LIBLTE_MME_MSG_TYPE_ATTACH_REQUEST:
            srsran::console("UL NAS: Attach Resquest\n");
            if (!handle_attach_request(pdu.get())) {
                srsran::console("failed to parse nas pdu\n");
            }
            break;
        case LIBLTE_MME_MSG_TYPE_IDENTITY_RESPONSE:
            srsran::console("UL NAS: Received Identity Response\n");
            break;
        case LIBLTE_MME_MSG_TYPE_AUTHENTICATION_RESPONSE:
            srsran::console("UL NAS: Received Authentication Response\n");
             break;
        case LIBLTE_MME_MSG_TYPE_AUTHENTICATION_FAILURE:
            srsran::console("UL NAS: Authentication Failure\n");
            break;
        case LIBLTE_MME_MSG_TYPE_DETACH_REQUEST:
            srsran::console("UL NAS: Detach Request\n");
            break;
        case LIBLTE_MME_MSG_TYPE_SECURITY_MODE_COMPLETE:
            srsran::console("UL NAS: Received Security Mode Complete\n");           
            break;
        case LIBLTE_MME_MSG_TYPE_ATTACH_COMPLETE:
            srsran::console("UL NAS: Received Attach Complete\n");           
            break;
        case LIBLTE_MME_MSG_TYPE_ESM_INFORMATION_RESPONSE:
            srsran::console("UL NAS: Received ESM Information Response\n");
            break;
        case LIBLTE_MME_MSG_TYPE_TRACKING_AREA_UPDATE_REQUEST:
            srsran::console("UL NAS: Tracking Area Update Request\n");
            break;
        case LIBLTE_MME_MSG_TYPE_PDN_CONNECTIVITY_REQUEST:
            srsran::console("UL NAS: PDN Connectivity Request\n");
            break;
        default:
            srsran::console("Unhandled NAS integrity protected message %s\n", liblte_nas_msg_type_to_string(msg_type));
    }
}
static bool handle_attach_request(srsran::byte_buffer_t* nas_rx) {
    
  uint32_t m_tmsi      = 0;
  uint64_t imsi        = 0;
  LIBLTE_MME_ATTACH_REQUEST_MSG_STRUCT attach_req  = {};
  LIBLTE_MME_PDN_CONNECTIVITY_REQUEST_MSG_STRUCT pdn_con_req = {};

  // Get NAS Attach Request and PDN connectivity request messages
  LIBLTE_ERROR_ENUM err = liblte_mme_unpack_attach_request_msg((LIBLTE_BYTE_MSG_STRUCT*)nas_rx, &attach_req);
  if (err != LIBLTE_SUCCESS) {
    srsran::console("Error unpacking NAS attach request. Error: %s", liblte_error_text[err]);
    return false;
  }
  // Get PDN Connectivity Request*/
  err = liblte_mme_unpack_pdn_connectivity_request_msg(&attach_req.esm_msg, &pdn_con_req);
  if (err != LIBLTE_SUCCESS) {
    srsran::console("Error unpacking NAS PDN Connectivity Request. Error: %s", liblte_error_text[err]);
    return false;
  }

  // Get UE IMSI
  if (attach_req.eps_mobile_id.type_of_id == LIBLTE_MME_EPS_MOBILE_ID_TYPE_IMSI) {
    for (int i = 0; i <= 14; i++) {
      imsi += attach_req.eps_mobile_id.imsi[i] * std::pow(10, 14 - i);
    }
    srsran::console("Attach request -- IMSI: %015" PRIu64 "\n", imsi);
  } else if (attach_req.eps_mobile_id.type_of_id == LIBLTE_MME_EPS_MOBILE_ID_TYPE_GUTI) {
    m_tmsi = attach_req.eps_mobile_id.guti.m_tmsi;
    srsran::console("Attach request -- M-TMSI: 0x%x\n", m_tmsi);
  } else {
    srsran::console("Unhandled Mobile Id type in attach request");
    return false;
  }
  return true;
}

// ---------------------- 读取数据块 ----------------------
static std::vector<std::string> split_on_blank_lines(const std::string& s) {
    std::vector<std::string> chunks;
    size_t i = 0, n = s.size();
    while (i < n) {
        size_t j = i;
        while (j < n) {
            if (s[j] == '\n') {
                size_t k = j;
                while (k < n && s[k] == '\n') ++k;
                if (k - j >= 2) {
                    break;
                }
                j = k;
            } else {
                ++j;
            }
        }
        std::string piece = s.substr(i, j - i);
        piece.erase(std::remove_if(piece.begin(), piece.end(), ::isspace), piece.end()); // 移除空格和换行符
        if (!piece.empty()) {
            chunks.push_back(piece);
        }
        if (j >= n) break;
        while (j < n && s[j] == '\n') ++j;
        i = j;
    }
    return chunks;
}