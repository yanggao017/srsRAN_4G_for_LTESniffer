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

static bool handle_attach_request(srsran::byte_buffer_t* nas_rx);
static void parse_ul_dcch(uint32_t lcid, srsran::unique_byte_buffer_t pdu);
static void handle_rrc_con_setup_complete(rrc_conn_setup_complete_s* msg, srsran::unique_byte_buffer_t pdu);
static void hex_string_to_byte_array(const char* hex_string, uint8_t* byte_array);

int main(int argc, char** argv) {
    std::string input_file;
    for (int i = 1; i < argc; ++i) {
        if (std::string(argv[i]) == "-i" && i + 1 < argc) {
            input_file = argv[i + 1];
            break;
        }
    }
    if (!input_file.empty()) {
        std::ifstream ifs(input_file);
        if (!ifs.is_open()) {
            printf("\033[1;31m[x] 无法打开文件: %s\033[0m\n", input_file.c_str());
            return 1;
        }
        std::string hex_input((std::istreambuf_iterator<char>(ifs)),
                              std::istreambuf_iterator<char>());
        ifs.close();

        // 去掉换行或空格
        hex_input.erase(std::remove_if(hex_input.begin(), hex_input.end(),
                                       [](unsigned char c){ return std::isspace(c); }),
                        hex_input.end());

        size_t rrc_payload_len = hex_input.size() / 2;
        std::cout << "解析得到字节长度: " << rrc_payload_len << " bytes" << std::endl;

        uint8_t* rrc_ptr = new uint8_t[rrc_payload_len];
        hex_string_to_byte_array(hex_input.c_str(), rrc_ptr);

        std::cout << "转换后的字节流: ";
        for (size_t i = 0; i < rrc_payload_len; i++) {
            std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)rrc_ptr[i];
        }
        std::cout << std::dec << std::endl;
        srsran::unique_byte_buffer_t rrc_pdu = srsran::make_byte_buffer();
        memcpy(rrc_pdu->msg, rrc_ptr, rrc_payload_len);
        rrc_pdu->N_bytes = rrc_payload_len;
        parse_ul_dcch(1, std::move(rrc_pdu));       
    }
    return 0;
}

static void parse_ul_dcch(uint32_t lcid, srsran::unique_byte_buffer_t pdu)
{
    uint32_t len = pdu->N_bytes;
    uint8_t* msg = pdu->msg;
    std::cout << "RRC PDU 内容 (hex): ";
    for (uint32_t i = 0; i < len; i++) {
        std::cout << std::hex << std::uppercase << std::setw(2) << std::setfill('0') << (int)msg[i] << " ";
    }
    std::cout << std::dec << std::endl;

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
    
  uint32_t                                       m_tmsi      = 0;
  uint64_t                                       imsi        = 0;
  LIBLTE_MME_ATTACH_REQUEST_MSG_STRUCT           attach_req  = {};
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

static void hex_string_to_byte_array(const char* hex_string, uint8_t* byte_array)
{
    size_t len = strlen(hex_string);
    for (size_t i = 0; i < len; i += 2)
        sscanf(hex_string + i, "%2hhx", &byte_array[i / 2]);
}