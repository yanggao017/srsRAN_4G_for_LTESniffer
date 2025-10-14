#include "srsran/common/common.h" // 引入srsRAN库的公共头文件
#include "srsran/common/interfaces_common.h"
#include "srsran/common/mac_pcap.h" // MAC层PCAP记录
#include "srsran/common/test_common.h"
#include "srsran/mac/pdu.h" // MAC PDU处理
#include "srsran/rlc/rlc_am_base.h" // RLC AM模式，有重传机制，高可靠性
#include "srsran/rlc/rlc_common.h"
#include "srsran/rlc/rlc_am_lte.h" // LTE RLC AM模式
#include "srsran/asn1/liblte_mme.h" // MME ASN.1编解码


extern "C" {
// C++中嵌入C语言头文件
#include "srsran/phy/phch/dci.h" // 下行控制信息
}

#include <bitset>
#include <iostream>
#include <map>
#include <random>

#define HAVE_PCAP 0

std::random_device rd; // 创建一个对象用于生成随机数
std::mt19937 rand_gen(rd());
std::uniform_int_distribution<uint8_t> uniform_dist_u8(0, 255);

static std::unique_ptr<srsran::mac_pcap> pcap_handle = nullptr;

using namespace srsran;

#define TEST_CRNTI (0x1001)

// TV1 contains a RAR PDU for a single RAPID and no backoff indication
#define RAPID_TV1 (42)
#define TA_CMD_TV1 (8)
uint8_t rar_pdu_tv1[] = {0x6a, 0x00, 0x80, 0x00, 0x0c, 0x10, 0x01};

// TV2 contains a RAR PDU for a single RAPID and also includes a backoff indication subheader
#define RAPID_TV2 (22)
#define BACKOFF_IND_TV2 (2)
#define TA_CMD_TV2 (0)
uint8_t rar_pdu_tv2[] = {0x82, 0x56, 0x00, 0x00, 0x00, 0x0c, 0x10, 0x01};

void hex_string_to_byte_array(const char* hex_string, uint8_t* byte_array)
{
    size_t len = strlen(hex_string); // size_t 是一个无符号整数类型
    for (size_t i = 0; i < len; i += 2)
    {
        sscanf(hex_string + i, "%2hhx", &byte_array[i / 2]); // 从字符串中读取格式化的数据
    }
}

void hexdump(uint8_t* data, size_t length)
{
    for (size_t i = 0; i < length; i += 16)
    {
        printf("%08zx: ", i);
        for (size_t j = 0; j < 16 && (i + j) < length; ++j)
        {
            printf("%02X ", data[i + j]);
        }
        printf("\n");
    }
    printf("\n");
}

// Helper class to provide read_pdu_interface
class rlc_dummy : public srsran::read_pdu_interface
{
public:
    uint32_t read_pdu(uint32_t lcid, uint8_t* payload, uint32_t nof_bytes)
    {
        uint32_t len = std::min(ul_queues[lcid], nof_bytes);

        // set payload bytes to LCID so we can check later if the scheduling was correct
        memset(payload, lcid, len);

        // remove from UL queue
        ul_queues[lcid] -= len;

        return len;
    };

    void write_sdu(uint32_t lcid, uint32_t nof_bytes) { ul_queues[lcid] += nof_bytes; }

private:
    // UL queues where key is LCID and value the queue length
    std::map<uint32_t, uint32_t> ul_queues;
};


void print_amd_pdu_header(srsran::rlc_amd_pdu_header_t& header)
{
    printf("\n====== RLC AMD PDU Header ======\n");
    printf("dc (Data or Control): %d - %s\n", header.dc, header.dc == 1 ? "Data PDU" : "Control PDU");
    printf("rf (Resegmentation Flag): %d\n", header.rf);
    printf("p (Polling Bit): %d\n", header.p);
    printf("fi (Framing Info): %d\n", header.fi);
    printf("sn (Sequence Number): %d\n", header.sn);
    printf("lsf (Last Segment Flag): %d\n", header.lsf);
    printf("so (Segment Offset): %d\n", header.so);
    printf("N_li (Number of Length Indicators): %d\n", header.N_li);
    printf("li (Length Indicators): ");
    for (uint32_t i = 0; i < header.N_li; i++)
    {
        printf("%d ", header.li[i]);
    }
    printf("\n================================\n");
}

void uint8_to_uint16(uint8_t* buf, uint16_t* i)
{
    *i = (uint32_t)buf[0] << 8 | (uint32_t)buf[1];
}


void uint8_to_uint24(uint8_t* buf, uint32_t* i)
{
    *i = (uint32_t)buf[0] << 16 | (uint32_t)buf[1] << 8 | (uint32_t)buf[2];
}

uint32_t SN(uint32_t count, uint32_t sn_len)
{
    return count & (0xFFFFFFFF >> (32 - sn_len));
}

uint32_t read_data_header(const unique_byte_buffer_t& pdu, uint32_t sn_len)
{
    // Extract RCVD_SN
    uint16_t rcvd_sn_16 = 0;
    uint32_t rcvd_sn_32 = 0;
    switch (sn_len)
    {
    case PDCP_SN_LEN_5:
        rcvd_sn_32 = SN(pdu->msg[0], sn_len);
        break;
    case PDCP_SN_LEN_7:
        rcvd_sn_32 = SN(pdu->msg[0], sn_len);
        break;
    case PDCP_SN_LEN_12:
        uint8_to_uint16(pdu->msg, &rcvd_sn_16);
        rcvd_sn_32 = SN(rcvd_sn_16, sn_len);
        break;
    case PDCP_SN_LEN_18:
        uint8_to_uint24(pdu->msg, &rcvd_sn_32);
        rcvd_sn_32 = SN(rcvd_sn_32, sn_len);
        break;
    default:
        printf("Cannot extract RCVD_SN, invalid SN length configured: %d\n", sn_len);
    }

    return rcvd_sn_32;
}

void my_pack_pdcp_info(uint8_t* sdu_ptr, uint32_t payload_len, uint32_t lcid)
{
    srsran::unique_byte_buffer_t pdcp_pdu = srsran::make_byte_buffer();
    pdcp_pdu->N_bytes = payload_len;
    memcpy(pdcp_pdu->msg, sdu_ptr, pdcp_pdu->N_bytes);
    uint8_t pd, msg_type, sec_hdr_type;
    liblte_mme_parse_msg_sec_header((LIBLTE_BYTE_MSG_STRUCT*)pdcp_pdu.get(), &pd, &sec_hdr_type);
    if ((sec_hdr_type == LIBLTE_MME_SECURITY_HDR_TYPE_PLAIN_NAS) ||
        (sec_hdr_type == LIBLTE_MME_SECURITY_HDR_TYPE_INTEGRITY) ||
        (sec_hdr_type == LIBLTE_MME_SECURITY_HDR_TYPE_INTEGRITY_WITH_NEW_EPS_SECURITY_CONTEXT) || true)
    {
        printf("====【test yg】PDCP PDU ===\n");
        printf(" PDCP PDU:\n");
        //(sdu_ptr, payload_len);
        uint32_t pdcp_sn;
        if (lcid <= 2)
        {
            pdcp_sn = read_data_header(pdcp_pdu, 5);
        }
        else
        {
            pdcp_sn = read_data_header(pdcp_pdu, 12);
        }

        printf(" pdcp sec_hdr_type:%d\n", sec_hdr_type);

        printf(" pdcp_sn:%d\n", pdcp_sn);

        printf(" payload_len:%d\n", payload_len);

        printf("==== PDCP PDU ===\n");
    }
}

/**
 * @param sdu_ptr: 指向 RLC PDU 数据的指针
 * @param payload_length: RLC PDU 的有效载荷长度
 * @param lcid: 逻辑信道 ID
 */
void my_pack_rlc_info(uint8_t* sdu_ptr, const uint32_t payload_length, uint32_t lcid)
{
    if (!rlc_am_is_control_pdu(sdu_ptr)) // 若当前 PDU 不是 RLC AM 控制 PDU（如 ACK/NACK）
    {
        uint32_t payload_len = payload_length;
        rlc_amd_pdu_header_t header = {}; // RLC AM 数据 PDU 的头部结构，包含序列号、LI字段个数、分段长度数组
        rlc_am_read_data_pdu_header(&sdu_ptr, &payload_len, &header); // 从 sdu_ptr 解析头部，并更新指针和剩余长度
        print_amd_pdu_header(header); // 打印头部信息（调试用）
        uint32_t len = 0;
        unique_byte_buffer_t rx_sdu = srsran::make_byte_buffer(); // 初始化接收缓冲区
        rlc_amd_rx_pdu pdu; // 临时存储原始 PDU 数据和头部信息
        pdu.buf = srsran::make_byte_buffer();
        pdu.buf->set_timestamp();

        memcpy(pdu.buf->msg, sdu_ptr, payload_len);
        pdu.buf->N_bytes = payload_len;
        pdu.header = header;
        // Handle any SDU segments
        for (uint32_t i = 0; i < header.N_li; i++)
        {
            len = header.li[i];
            if (len == 0)
            {
                break;
            }
            if (rx_sdu->get_tailroom() >= len)
            {
                if ((pdu.buf->msg - pdu.buf->buffer) + len < SRSRAN_MAX_BUFFER_SIZE_BYTES)
                {
                    memcpy(&rx_sdu->msg[rx_sdu->N_bytes], pdu.buf->msg, len);
                    rx_sdu->N_bytes += len;
                    //rx_sdu->print_info(cur_rnti, tti, lcid);
                    my_pack_pdcp_info(rx_sdu->msg, rx_sdu->N_bytes, lcid);
                    pdu.buf->msg += len;
                    pdu.buf->N_bytes -= len;
                    //parent->pdcp->write_pdu(parent->lcid, std::move(rx_sdu));
                    rx_sdu = srsran::make_byte_buffer();
                }
                else
                {
                    printf("Cannot read  bytes from rx_window. vr_r=, msg-buffer= B");
                    rx_sdu.reset();
                }
            }
            else
            {
                printf("Cannot fit RLC PDU in SDU buffer, dropping both.");
                rx_sdu.reset();
            }
        }
        len = pdu.buf->N_bytes;
        if (rx_sdu->get_tailroom() >= len)
        {
            memcpy(&rx_sdu->msg[rx_sdu->N_bytes], pdu.buf->msg, len);
            rx_sdu->N_bytes += pdu.buf->N_bytes;
            //rx_sdu->print_info(cur_rnti, tti, lcid);
            my_pack_pdcp_info(rx_sdu->msg, rx_sdu->N_bytes, lcid);
        }
        else
        {
            rx_sdu.reset(); // 释放内存
        }
    }
}

int mac_sch_pdu_unpack_test5(const char* mac_msg_hex_stream) // 解析mac层数据单元(PDU)
{
    // const char* test_mac_pdu_hex = "3a3e212a1f3f000000a000002000402f60e6f6dc0c0e820217ec01e220000234773e598205e0e000080403a02323c000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
    const char* test_mac_pdu_hex =
        "3a3e212a1f3f000000a000002000402f60e6f6dc0c0e820217ec01e220000234773e598205e0e000080403a02323c000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
    size_t byte_array_length = strlen(test_mac_pdu_hex) / 2;
    uint8_t mac_pdu_tv5[byte_array_length]; // 创建一个字节数组存储
    hex_string_to_byte_array(test_mac_pdu_hex, mac_pdu_tv5);
    // hexdump(mac_pdu_tv5,byte_array_length);

    srsran::sch_pdu pdu(20, srslog::fetch_basic_logger("MAC")); // 创建 MAC PDU 解析器
    pdu.init_rx(sizeof(mac_pdu_tv5), true); // 初始化接收缓冲区
    pdu.parse_packet(mac_pdu_tv5); // 解析 MAC PDU

    int nof_subh = pdu.nof_subh(); // 获取子头数量
    printf("[+] 当前 mac-pdu 的子头总数: %d\n", nof_subh);

    int i = 0;
    while (pdu.next()) // 遍历子头
    {
        srsran::sch_subh* subh = pdu.get(); // get()返回的是指向当前子头的指针
        printf("\033[32m[+] 子头 %d: %s\n\033[0m", i, subh->is_sdu() ? "MAC-SDU(RLC-PDU)" : "MAC-CE");
        // 判断当前子头是 MAC SDU（RLC PDU） 还是 MAC CE（控制元素）
        if (subh->is_sdu()) // 如果是RLC-PDU
        {
            uint8_t* my_sdu_ptr = pdu.get()->get_sdu_ptr(); // 获取 RLC PDU 指针
            int payload_length = pdu.get()->get_payload_size(); // 获取 RLC PDU 长度
            uint32_t lcid = subh->get_sdu_lcid(); // 获取逻辑信道ID(LCID)
            uint8_t* payload = subh->get_sdu_ptr();
            // hexdump(payload, payload_length);
            printf("RLC SDU: LCID = %u, Length = %u\n", lcid, payload_length);
            my_pack_rlc_info(my_sdu_ptr, payload_length, lcid); // 自定义函数，处理 RLC PDU
        }
        else
        {
            auto ce_type = subh->ul_sch_ce_type();
            switch (ce_type)
            {
            case srsran::ul_sch_lcid::LONG_BSR:
                {
                    uint32_t bsr_idx[4] = {0}, bsr_bytes[4] = {0};
                    subh->get_bsr(bsr_idx, bsr_bytes);
                    printf("  LONG BSR:\n");
                    for (int j = 0; j < 4; ++j)
                    {
                        if (bsr_idx[j] > 0)
                        {
                            printf("    LCG%d = %u bytes (idx=%u)\n", j, bsr_bytes[j], bsr_idx[j]);
                        }
                    }
                    break;
                }

            case srsran::ul_sch_lcid::SHORT_BSR:
            case srsran::ul_sch_lcid::TRUNC_BSR:
                {
                    uint32_t bsr_idx[4] = {0}, bsr_bytes[4] = {0};
                    uint32_t lcg = subh->get_bsr(bsr_idx, bsr_bytes);
                    printf("  %s: LCG%d = %u bytes (idx=%u)\n",
                           ce_type == srsran::ul_sch_lcid::SHORT_BSR ? "SHORT BSR" : "TRUNC BSR",
                           lcg, bsr_bytes[lcg], bsr_idx[lcg]);
                    break;
                }

            case srsran::ul_sch_lcid::PHR_REPORT:
                {
                    float phr = subh->get_phr();
                    printf("  Power Headroom Report = %.1f dB\n", phr);
                    break;
                }

            case srsran::ul_sch_lcid::PHR_REPORT_EXT:
                {
                    printf("  Extended Power Headroom Report (not parsed)\n");
                    break;
                }

            case srsran::ul_sch_lcid::CRNTI:
                {
                    uint16_t crnti = subh->get_c_rnti();
                    printf("  C-RNTI = 0x%04x (%u)\n", crnti, crnti);
                    break;
                }

            case srsran::ul_sch_lcid::PADDING:
                {
                    printf("  Padding (len = %u bytes)\n", subh->get_payload_size());
                    break;
                }

            default:
                {
                    printf("  Unknown or unsupported MAC CE type: %s\n", srsran::to_string(ce_type));
                    break;
                }
            }
        }
        i++;
    }
    return 1;
}

int main(int argc, char** argv)
// argc-命令行参数的总数量（包括程序名本身）
// argv-存储所有命令行参数的字符串形式
{
    std::cout << "[+] 程序开始运行" << std::endl;
#if HAVE_PCAP
    pcap_handle = std::unique_ptr<srsran::mac_pcap>(new srsran::mac_pcap());
    pcap_handle->open("mac_pdu_test.pcap");
#endif
    auto& mac_logger = srslog::fetch_basic_logger("MAC", false);
    mac_logger.set_level(srslog::basic_levels::debug);
    mac_logger.set_hex_dump_max_size(-1);
    auto& rlc_logger = srslog::fetch_basic_logger("RLC", false);
    rlc_logger.set_level(srslog::basic_levels::debug);
    rlc_logger.set_hex_dump_max_size(-1);

    srslog::init();
    std::string test_dir = "/home/yg/4G/rnti_collection/dataset/rlc/";
    std::string test_filefile = "test2.txt";
    std::string input_file = test_dir + test_filefile;
    // std::cout << input_file << std::endl;

    // 创建一个输入文件流对象，并尝试打开
    std::ifstream file;
    file.open(input_file);
    if (!file)
    {
        std::cerr << "Failed to open input file: " << input_file << "\n";
        return 1;
    }
    std::ostringstream buffer; // 创建一个输出字符串流对象 buffer
    buffer << file.rdbuf(); // 将文件的所有内容（从当前指针到末尾）一次性读取到 buffer 中
    std::string hex_str = buffer.str(); // 将 buffer 中存储的数据转换为普通字符串 hex_str
    file.close();
    // 去除空格、换行
    // remove_if-将所有非空白字符移到字符串前端，并返回一个指向新逻辑结尾的迭代器
    // str.erase()-从 new_end（remove_if 返回的迭代器）到字符串末尾的所有字符
    hex_str.erase(std::remove_if(hex_str.begin(), hex_str.end(), ::isspace), hex_str.end());
    char* mac_msg_hex_stream = new char[hex_str.size() + 1]; // 动态分配一个字符数组，+1是为了末尾的\0
    std::strcpy(mac_msg_hex_stream, hex_str.c_str());

    mac_sch_pdu_unpack_test5(mac_msg_hex_stream); // 解包并提取数据
    return SRSRAN_SUCCESS;
}