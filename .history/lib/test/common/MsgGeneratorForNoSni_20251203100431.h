#ifndef MSG_GENERATOR_FOR_NO_SNI_H
#define MSG_GENERATOR_FOR_NO_SNI_H
#pragma once
#include <cstring>
#include <iostream>
#include "log.h"
#include "srsran/srsran.h"
#include "srsran/asn1/asn1_utils.h"
#include "srsran/asn1/rrc.h"
#include "srsran/interfaces/pdcp_interface_types.h"
#include "srsran/rlc/rlc_common.h"
#include "srsran/rlc/rlc_am_lte_packing.h"
#include "srsran/mac/pdu.h"
#include "srsran/common/byte_buffer.h"
#include "srsran/common/common.h"
#include "srsran/common/mac_pcap.h"
#include "srsran/asn1/liblte_mme.h"

using asn1::rrc::;
class MsgGeneratorForNoSni {
public:
    MsgGeneratorForNoSni() = default;
    ~MsgGeneratorForNoSni() = default;

    void gen_identity_request_pdu(uint8_t* buffer, uint32_t* msg_len);
    void gen_attach_reject_pdu(uint8_t* buffer, uint32_t* msg_len);
    void gen_authen_reject_pdu(uint8_t* buffer, uint32_t* msg_len);
    void gen_authen_request_pdu(uint8_t* buffer, uint32_t* msg_len);
    void gen_attach_accept_pdu(uint8_t* buffer, uint32_t* msg_len);
    void gen_sec_mod_comm_pdu(uint8_t* buffer, uint32_t* msg_len);
    void gen_detach_accept_pdu(uint8_t* buffer, uint32_t* msg_len);
    void gen_detach_request_pdu(uint8_t* buffer, uint32_t* msg_len);
    void gen_service_reject_pdu(uint8_t* buffer, uint32_t* msg_len);
    void gen_pdn_connectivity_reject_pdu(uint8_t* buffer, uint32_t* msg_len);
    void gen_rrc_connection_release_pdu(uint8_t* buffer, uint32_t* msg_len);
    void gen_rrc_connection_reest_reject_pdu(uint8_t* buffer, uint32_t* msg_len);
    void gen_deactivate_eps_bearer_request_pdu(uint8_t* buffer, uint32_t* msg_len);
    void setEMMCause(uint32_t cause) {emm_cause = cause;};
    void setESMCause(uint32_t cause) {esm_cause = cause;};
private:
    uint32_t emm_cause = 3;
    uint32_t esm_cause = 26;
    void uint16_to_uint8(uint16_t i, uint8_t* buf);
    void uint24_to_uint8(uint32_t i, uint8_t* buf);
    void hex_string_to_byte_array(const char* hex_string, uint8_t* byte_array);
    void print_hex_stream(const uint8_t* data, size_t length);
    void hexdump(uint8_t* data, size_t length);

    // ===== NAS 层构造函数 =====
    void gen_identity_request_nas(srsran::unique_byte_buffer_t& msg);
    void gen_attach_reject_nas(srsran::unique_byte_buffer_t& msg);
    void gen_authen_reject_nas(srsran::unique_byte_buffer_t& msg);
    void gen_authen_request_nas(srsran::unique_byte_buffer_t& msg);
    void gen_attach_accept_nas_plain(srsran::unique_byte_buffer_t& msg);
    void gen_attach_accept_nas_inpro(srsran::unique_byte_buffer_t& msg);
    void gen_sec_mod_comm_nas(srsran::unique_byte_buffer_t& msg);
    void gen_detach_accept_nas(srsran::unique_byte_buffer_t& msg);
    void gen_detach_request_nas(srsran::unique_byte_buffer_t& msg);
    void gen_service_reject_nas(srsran::unique_byte_buffer_t& msg);
    void gen_pdn_connectivity_reject_nas(struct LIBLTE_BYTE_MSG_STRUCT* msg);
    void gen_attach_reject_pdn_connectivity_reject_nas(srsran::unique_byte_buffer_t& msg);

    void gen_deactivate_eps_bearer_request_nas(srsran::unique_byte_buffer_t& msg);



    // ===== 协议栈封装函数 =====
    bool build_rrc_dl_info_transfer(
        srsran::unique_byte_buffer_t nas_pdu,
        srsran::unique_byte_buffer_t& rrc_pdu);

    bool build_rrc_dl_info_transfer_rrc_con_rel(
        srsran::unique_byte_buffer_t nas_pdu,
        srsran::unique_byte_buffer_t& rrc_pdu);

    bool add_pdcp_header(
        srsran::unique_byte_buffer_t& rrc_pdu,
        uint32_t pdcp_sn,
        uint8_t sn_len);

    bool build_rlc_am_pdu(
        const srsran::unique_byte_buffer_t& pdcp_sdu,
        uint16_t rlc_sn,
        uint8_t* rlc_buffer,
        size_t buffer_size,
        size_t* out_rlc_len);

    bool build_mac_pdu(
        uint8_t* rlc_sdu,
        size_t rlc_sdu_len,
        uint8_t* mac_buffer,
        uint32_t* out_mac_len);

    bool build_dl_mac_pdu_from_nas(
        srsran::unique_byte_buffer_t nas_pdu,
        uint32_t pdcp_sn,
        uint16_t rlc_sn,
        uint8_t pdcp_sn_len_bits,
        uint8_t* output_buffer,
        uint32_t* out_msg_len);

    bool build_dl_mac_pdu_from_rrc(
        srsran::unique_byte_buffer_t rrc_pdu,
        uint32_t pdcp_sn,
        uint16_t rlc_sn,
        uint8_t pdcp_sn_len_bits,
        uint8_t* output_buffer,
        uint32_t* out_msg_len);
};

#endif // MSG_GENERATOR_FOR_NO_SNI_H