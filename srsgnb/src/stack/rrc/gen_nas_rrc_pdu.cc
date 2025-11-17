#include "srsgnb/hdr/stack/rrc/rrc_nr_ue.h"
#include "srsgnb/hdr/stack/rrc/cell_asn1_config.h"
#include "srsgnb/hdr/stack/rrc/rrc_nr_config_utils.h"
#include "srsran/asn1/rrc_nr_utils.h"
#include "srsran/common/bearer_manager.h"
#include "srsran/common/standard_streams.h"
#include "srsran/common/string_helpers.h"
#include "srsran/asn1/rrc/dl_dcch_msg.h"
#include <iostream>
#include <stdio.h>

#include "srsran/asn1/nas_5g_msg.h"
#include "srsran/common/buffer_pool.h"
#include "srsran/common/nas_pcap.h"
#include "srsran/common/test_common.h"
#include "srsran/srslog/srslog.h"
using namespace asn1;
using namespace asn1::rrc_nr;

void gen_nas_pdu() {
     //uint8_t sec_command[] = {0x7e, 0x00, 0x58};
   uint8_t sec_command[] = {0x7e, 0x00, 0x60};

    srsran::unique_byte_buffer_t nas_tx;
    copy_msg_to_buffer(nas_tx, sec_command);
    printf("NAS Message (%d bytes): ", nas_tx->N_bytes);
    for (uint32_t i = 0; i < nas_tx->N_bytes; ++i) {
        printf("%02x ", nas_tx->msg[i]);
    }
    printf("\n");
    dl_dcch_msg_s dl_dcch_msg;
    dl_dcch_msg.msg.set_c1().set_dl_info_transfer().rrc_transaction_id = (uint8_t)(0 % 4);
    dl_info_transfer_ies_s& ies = dl_dcch_msg.msg.c1().dl_info_transfer().crit_exts.set_dl_info_transfer();

    ies.ded_nas_msg.resize(nas_tx->N_bytes);
    memcpy(ies.ded_nas_msg.data(), nas_tx->data(), ies.ded_nas_msg.size());

    srsran::unique_byte_buffer_t pdu;
    if (pdu == nullptr) {
        pdu = srsran::make_byte_buffer();
        if (pdu == nullptr) {
        }
    }
    asn1::bit_ref bref(pdu->msg, pdu->get_tailroom());
    if (dl_dcch_msg.pack(bref) == asn1::SRSASN_ERROR_ENCODE_FAIL) {
        printf("Failed to encode DL-DCCH-Msg");
    }
    pdu->N_bytes = (uint32_t)bref.distance_bytes();
    printf("RRC Message (%d bytes): ", pdu->N_bytes);
        for (uint32_t i = 0; i < pdu->N_bytes; ++i) {
        printf("%02x ", pdu->msg[i]);
    }
    printf("\n");
}

void gen_rrc_release()
{
    static const uint32_t release_delay = 60; // Taken from TS 38.331, 5.3.8.3

    dl_dcch_msg_s  dl_dcch_msg;
    rrc_release_s& release = dl_dcch_msg.msg.set_c1().set_rrc_release();

    release.rrc_transaction_id = (uint8_t)(0 % 4);
    rrc_release_ies_s& ies     = release.crit_exts.set_rrc_release();

    ies.suspend_cfg_present = false; // goes to RRC_IDLE

    srsran::unique_byte_buffer_t pdu;
    if (pdu == nullptr) {
        pdu = srsran::make_byte_buffer();
        if (pdu == nullptr) {
        }
    }
    asn1::bit_ref bref(pdu->msg, pdu->get_tailroom());
    if (dl_dcch_msg.pack(bref) == asn1::SRSASN_ERROR_ENCODE_FAIL) {
        printf("Failed to encode DL-DCCH-Msg");
    }
    pdu->N_bytes = (uint32_t)bref.distance_bytes();
    printf("RRC Message (%d bytes): ", pdu->N_bytes);
        for (uint32_t i = 0; i < pdu->N_bytes; ++i) {
        printf("%02x ", pdu->msg[i]);
    }
    printf("\n");
}
/// TS 38.331, RRCReject message
void gen_rrc_reject()
{
    uint8_t reject_wait_time_secs =  16;
    dl_ccch_msg_s     msg;
    rrc_reject_ies_s& reject = msg.msg.set_c1().set_rrc_reject().crit_exts.set_rrc_reject();

    // See TS 38.331, RejectWaitTime
    if (reject_wait_time_secs > 0) {
        reject.wait_time_present = true;
        reject.wait_time         = reject_wait_time_secs;
    }
    srsran::unique_byte_buffer_t pdu;
    if (pdu == nullptr) {
        pdu = srsran::make_byte_buffer();
        if (pdu == nullptr) {
        }
    }
    asn1::bit_ref bref(pdu->msg, pdu->get_tailroom());
    if (msg.pack(bref) == asn1::SRSASN_ERROR_ENCODE_FAIL) {
        printf("Failed to encode DL-DCCH-Msg");
    }
    pdu->N_bytes = (uint32_t)bref.distance_bytes();
    printf("RRC Message (%d bytes): ", pdu->N_bytes);
        for (uint32_t i = 0; i < pdu->N_bytes; ++i) {
        printf("%02x ", pdu->msg[i]);
    }
    printf("\n");

}
/*
MAC头部 01 xx，xx=2+2+RRC长度+MAC长度
RLC头部 8001
PDCP头部 0001
RRC内容 
MAC内容 00 00 00 00
*/
int main()
{
  srslog::init();
  srsran::console("Testing 5G NAS packing and unpacking\n");
  //gen_nas_pdu();
  //gen_rrc_release();
  gen_rrc_reject();
  /*srsran::nas_pcap pcap;
  pcap.open("nas_5g_msg_test.pcap", 0, srsran::srsran_rat_t::nr);
  pcap->write_nas(buf.get()->msg, buf.get()->N_bytes);
  pcap.close();*/
  return 0;
}