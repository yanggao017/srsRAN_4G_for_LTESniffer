#include "srsran/srsran.h"
#include "srsran/asn1/asn1_utils.h"
#include "srsran/asn1/rrc.h"
#include "srsran/common/bcd_helpers.h"
#include "srsran/interfaces/pdcp_interface_types.h"
#include "srsran/rlc/rlc_common.h"
#include "srsran/rlc/rlc_am_lte_packing.h"
#include "srsran/mac/pdu.h"
#include "srsran/common/byte_buffer.h"
#include "srsran/common/common.h"
#include "srsran/common/interfaces_common.h"
#include "srsran/common/mac_pcap.h"
#include "srsran/asn1/liblte_mme.h"
#include "log.h"
using namespace asn1;
using namespace asn1::rrc;
const std::string cache_root = "./cache";  // 你的缓存根目录
std::string output_dir_str;          // 可变字符串
const char* output_dir = nullptr;    // 最终用于 legacy 接口

char sib1_path[512];
char sib2_path[512];
char mib_path[512];
char cell_config_path[512];

uint32_t imsi_to_array(std::string imsi_s, uint8_t* buff) {
  uint32_t len = imsi_s.length();
  unsigned long long imsi = std::stoull(imsi_s);
  for (int i = len-1; i >= 0; i--) {
    buff[i] = imsi%10;
    imsi = imsi/10;
  }
  return len;
}
void hex_string_to_byte_array(const char *hex_string, uint8_t *byte_array) {
  size_t len = strlen(hex_string);
  for (size_t i = 0; i < len; i += 2) {
      sscanf(hex_string + i, "%2hhx", &byte_array[i / 2]);
  }
}
uint32_t SN(uint32_t count)
{    
  uint8_t sn_len = 5;
  return count & (0xFFFFFFFF >> (32 - sn_len));
}

void my_write_data_header(uint8_t* msg, uint32_t count)
{
  int hdr_len_bytes = 1;
  msg -= hdr_len_bytes;
  uint8_t sn_len = 5;
  msg[0] = SN(count);
}
void hexdump(uint8_t* data, size_t length, bool print_compact = true) {
    // 标准 hex dump
    for (size_t i = 0; i < length; i += 16) {
        printf("%08zx: ", i);
        for (size_t j = 0; j < 16 && (i + j) < length; ++j) {
            printf("%02X ", data[i + j]);
        }
        printf("\n");
    }

    if (print_compact) {
        for (size_t i = 0; i < length; ++i) {
            printf("%02X", data[i]);
        }
        printf("\n");
    }
}
void append_mac(srsran::unique_byte_buffer_t& sdu, uint8_t* mac)
{
  if (sdu->N_bytes + 4 > sdu->get_tailroom()) {
    return;
  }
  memcpy(&sdu->msg[sdu->N_bytes], mac, 4);
  sdu->N_bytes += 4;
}

void print_rr_cfg_common(const rr_cfg_common_sib_s& rr_cfg_common) {
  // 打印扩展标志
  printf("  ext: %s\n", rr_cfg_common.ext ? "true" : "false");

  // 打印 RACH 配置
  printf("  rach_cfg_common:\n");
  printf("    ext: %s\n", rr_cfg_common.rach_cfg_common.ext ? "true" : "false");
  printf("    preamb_info:\n");
  printf("      nof_ra_preambs: %s\n", rr_cfg_common.rach_cfg_common.preamb_info.nof_ra_preambs.to_string());
  if (rr_cfg_common.rach_cfg_common.preamb_info.preambs_group_a_cfg_present) {
      printf("      preambs_group_a_cfg_present: true\n");
      printf("      size_of_ra_preambs_group_a: %s\n", rr_cfg_common.rach_cfg_common.preamb_info.preambs_group_a_cfg.size_of_ra_preambs_group_a.to_string());
      printf("      msg_size_group_a: %s\n", rr_cfg_common.rach_cfg_common.preamb_info.preambs_group_a_cfg.msg_size_group_a.to_string());
      printf("      msg_pwr_offset_group_b: %s\n", rr_cfg_common.rach_cfg_common.preamb_info.preambs_group_a_cfg.msg_pwr_offset_group_b.to_string());
  } else {
      printf("      preambs_group_a_cfg_present: false\n");
  }
  printf("    ra_supervision_info:\n");
  printf("      preamb_trans_max: %s\n", rr_cfg_common.rach_cfg_common.ra_supervision_info.preamb_trans_max.to_string());
  printf("      ra_resp_win_size: %s\n", rr_cfg_common.rach_cfg_common.ra_supervision_info.ra_resp_win_size.to_string());
  printf("      mac_contention_resolution_timer: %s\n", rr_cfg_common.rach_cfg_common.ra_supervision_info.mac_contention_resolution_timer.to_string());
  printf("    max_harq_msg3_tx: %u\n", rr_cfg_common.rach_cfg_common.max_harq_msg3_tx);
  if (rr_cfg_common.rach_cfg_common.preamb_trans_max_ce_r13_present) {
      printf("    preamb_trans_max_ce_r13_present: true\n");
      printf("    preamb_trans_max_ce_r13: %s\n", rr_cfg_common.rach_cfg_common.preamb_trans_max_ce_r13.to_string());
  } else {
      printf("    preamb_trans_max_ce_r13_present: false\n");
  }

  // 打印 BCCH 配置
  printf("  bcch_cfg:\n");
  printf("    mod_period_coeff: %s\n", rr_cfg_common.bcch_cfg.mod_period_coeff.to_string());

  // 打印 PCCH 配置
  printf("  pcch_cfg:\n");
  printf("    default_paging_cycle: %s\n", rr_cfg_common.pcch_cfg.default_paging_cycle.to_string());
  printf("    nb: %s\n", rr_cfg_common.pcch_cfg.nb.to_string());

  // 打印 PRACH 配置
  printf("  prach_cfg:\n");
  printf("    root_seq_idx: %u\n", rr_cfg_common.prach_cfg.root_seq_idx);
  // 假设 prach_cfg_info 具有成员打印函数
  printf("    prach_cfg_info details not shown here.\n");

  // 打印 PDSCH 配置
  printf("  pdsch_cfg_common:\n");
  printf("    ref_sig_pwr: %d dBm\n", rr_cfg_common.pdsch_cfg_common.ref_sig_pwr);
  printf("    p_b: %u\n", rr_cfg_common.pdsch_cfg_common.p_b);
  printf("  pusch_cfg_common:\n");
  printf("    pusch_cfg_basic:\n");
  printf("      n_sb: %u\n", rr_cfg_common.pusch_cfg_common.pusch_cfg_basic.n_sb);
  printf("      hop_mode: %s\n", rr_cfg_common.pusch_cfg_common.pusch_cfg_basic.hop_mode.to_string());
  printf("      pusch_hop_offset: %u\n", rr_cfg_common.pusch_cfg_common.pusch_cfg_basic.pusch_hop_offset);
  printf("      enable64_qam: %s\n", rr_cfg_common.pusch_cfg_common.pusch_cfg_basic.enable64_qam ? "true" : "false");
  printf("  pucch_cfg_common:\n");
  printf("    delta_pucch_shift: %s\n", rr_cfg_common.pucch_cfg_common.delta_pucch_shift.to_string());
  printf("    nrb_cqi: %u\n", rr_cfg_common.pucch_cfg_common.nrb_cqi);
  printf("    ncs_an: %u\n", rr_cfg_common.pucch_cfg_common.ncs_an);
  printf("    n1_pucch_an: %u\n", rr_cfg_common.pucch_cfg_common.n1_pucch_an);
  printf("  srs_ul_cfg_common:\n");
  if (rr_cfg_common.srs_ul_cfg_common.type() == srs_ul_cfg_common_c::types::setup) {
      const auto& setup = rr_cfg_common.srs_ul_cfg_common.setup();
      printf("    srs_max_up_pts_present: %s\n", setup.srs_max_up_pts_present ? "true" : "false");
      printf("    srs_bw_cfg: %s\n", setup.srs_bw_cfg.to_string());
      printf("    srs_sf_cfg: %s\n", setup.srs_sf_cfg.to_string());
      printf("    ack_nack_srs_simul_tx: %s\n", setup.ack_nack_srs_simul_tx ? "true" : "false");
  } else {
      printf("    SRS UL Config is not setup.\n");
  }
  printf("  ul_pwr_ctrl_common:\n");
  printf("    p0_nominal_pusch: %d dBm\n", rr_cfg_common.ul_pwr_ctrl_common.p0_nominal_pusch);
  printf("    alpha: %s\n", rr_cfg_common.ul_pwr_ctrl_common.alpha.to_string());
  printf("    p0_nominal_pucch: %d dBm\n", rr_cfg_common.ul_pwr_ctrl_common.p0_nominal_pucch);
  printf("    delta_preamb_msg3: %d dB\n", rr_cfg_common.ul_pwr_ctrl_common.delta_preamb_msg3);
  printf("  ul_cp_len: %s\n", rr_cfg_common.ul_cp_len.to_string());
}

int print_sib2_fields(const sib_type2_s& verified_data) {
  printf("SIB2 Message Fields:\n");
  printf("ext: %s\n", verified_data.ext ? "true" : "false");
  printf("ac_barr_info_present: %s\n", verified_data.ac_barr_info_present ? "true" : "false");
  printf("mbsfn_sf_cfg_list_present: %s\n", verified_data.mbsfn_sf_cfg_list_present ? "true" : "false");
  printf("ac_barr_info:\n");
  printf("  ac_barr_for_mo_sig_present: %s\n", verified_data.ac_barr_info.ac_barr_for_mo_sig_present ? "true" : "false");
  printf("  ac_barr_for_mo_data_present: %s\n", verified_data.ac_barr_info.ac_barr_for_mo_data_present ? "true" : "false");
  printf("  ac_barr_for_emergency: %s\n", verified_data.ac_barr_info.ac_barr_for_emergency ? "true" : "false");
  if (verified_data.ac_barr_info.ac_barr_for_mo_sig_present) {
      printf("  ac_barr_for_mo_sig:\n");
      printf("    ac_barr_factor: %s\n", verified_data.ac_barr_info.ac_barr_for_mo_sig.ac_barr_factor.to_string());
      printf("    ac_barr_time: %s\n", verified_data.ac_barr_info.ac_barr_for_mo_sig.ac_barr_time.to_string());
      printf("    ac_barr_for_special_ac: %s\n", verified_data.ac_barr_info.ac_barr_for_mo_sig.ac_barr_for_special_ac.to_string().c_str());
  }
  if (verified_data.ac_barr_info.ac_barr_for_mo_data_present) {
      printf("  ac_barr_for_mo_data:\n");
      printf("    ac_barr_factor: %s\n", verified_data.ac_barr_info.ac_barr_for_mo_data.ac_barr_factor.to_string());
      printf("    ac_barr_time: %s\n", verified_data.ac_barr_info.ac_barr_for_mo_data.ac_barr_time.to_string());
      printf("    ac_barr_for_special_ac: %s\n", verified_data.ac_barr_info.ac_barr_for_mo_data.ac_barr_for_special_ac.to_string().c_str());
  }
  printf("rr_cfg_common:\n");
  print_rr_cfg_common(verified_data.rr_cfg_common);

  printf("ue_timers_and_consts:\n");
  printf("freq_info:\n");
  printf("  ul_carrier_freq_present: %s\n", verified_data.freq_info.ul_carrier_freq_present ? "true" : "false");
  printf("  ul_bw_present: %s\n", verified_data.freq_info.ul_bw_present ? "true" : "false");
  if (verified_data.freq_info.ul_carrier_freq_present) {
      printf("  ul_carrier_freq: %u Hz\n", verified_data.freq_info.ul_carrier_freq);
  } else {
      printf("  ul_carrier_freq: Not present\n");
  }

  if (verified_data.freq_info.ul_bw_present) {
      printf("  ul_bw: %s\n", verified_data.freq_info.ul_bw.to_string());
  } else {
      printf("  ul_bw: Not present\n");
  }

  printf("  add_spec_emission: %u\n", verified_data.freq_info.add_spec_emission);
  printf("mbsfn_sf_cfg_list:\n");
  return 1;
}

/**
 * @brief 从纯十六进制文本文件读取内容，转换为字节数组
 * @param filename 输入文件路径，如 "../output/sib2.hex"
 * @param byte_array 输出：动态分配的字节数组（需调用者 free）
 * @param byte_length 输出：字节数组长度
 * @return 0 表示成功，-1 表示失败（文件不存在、格式错误等）
 *
 * 要求：.hex 文件中只包含连续的十六进制字符（如 00aabbcc），无空格、换行等
 */
int read_hex_file_to_byte_array(const char* filename, uint8_t** byte_array, size_t* byte_length) {
  FILE* fp = fopen(filename, "r");
  if (!fp) {
      fprintf(stderr, "❌ Error: Cannot open file '%s'\n", filename);
      return -1;
  }
  fseek(fp, 0, SEEK_END);
  long file_size = ftell(fp);
  fseek(fp, 0, SEEK_SET);
  if (file_size == 0) {
      fprintf(stderr, "❌ Error: File '%s' is empty\n", filename);
      fclose(fp);
      return -1;
  }
  char* hex_str = (char*)malloc(file_size + 1);
  if (!hex_str) {
      fclose(fp);
      return -1;
  }
  size_t bytes_read = fread(hex_str, 1, file_size, fp);
  fclose(fp);

  if ((int)bytes_read != file_size) {
      free(hex_str);
      return -1;
  }
  hex_str[file_size] = '\0';
  for (int i = 0; i < file_size; i++) {
      if (!isxdigit((unsigned char)hex_str[i])) {
          fprintf(stderr, "❌ Error: Invalid hex character in file '%s'\n", filename);
          free(hex_str);
          return -1;
      }
  }
  if (file_size % 2 != 0) {
      fprintf(stderr, "❌ Error: Hex string has odd length in '%s'\n", filename);
      free(hex_str);
      return -1;
  }

  size_t len = file_size / 2;
  uint8_t* data = (uint8_t*)malloc(len);
  if (!data) {
      free(hex_str);
      return -1;
  }
  for (size_t i = 0; i < len; i++) {
      sscanf(hex_str + 2*i, "%2hhx", &data[i]);
  }
  free(hex_str);
  *byte_array = data;
  *byte_length = len;

  return 0;
}

int gen_paging_sysinfmod(uint8_t* buffer, uint32_t buffer_len, uint32_t* msg_len) {
  asn1::bit_ref bref(buffer, buffer_len);
  asn1::rrc::pcch_msg_s pcch_msg;
  pcch_msg.msg.set_c1();
  asn1::rrc::paging_s& paging = pcch_msg.msg.c1().paging();
  paging.sys_info_mod_present = true;
  if (pcch_msg.pack(bref) != SRSASN_SUCCESS) {
    return -1;
  }
  int len = bref.distance_bytes(buffer);
  srsran_vec_fprint_byte(stdout, buffer, len);
  *msg_len = len;
  return 0;
}

/**
 * @brief 生成带 ETWS 指示的 PCCH Paging 消息。
 *
 * Paging 里的 etws-Indication 是一个 presence-only 字段：
 * ASN.1 定义为 ENUMERATED { true } OPTIONAL，消息中只需要把该字段标记为存在，
 * 不携带具体的告警类型、serial number 或 warning text。UE 收到该指示后会重新读取
 * 承载 ETWS 内容的系统消息（如 SIB10/SIB11，具体内容不在 Paging 中承载）。
 *
 * 这里生成的是最小 ETWS Paging：
 * - pagingRecordList 不存在：不是针对某个 IMSI/S-TMSI 的寻呼。
 * - systemInfoModification 不存在：不同时触发普通系统消息变更指示。
 * - etws-Indication 存在：通知 UE 有 ETWS 相关系统消息需要关注。
 * - nonCriticalExtension 不存在：不携带 CMAS/eDRX/UAC 等后续版本扩展字段。
 */
int gen_paging_etws(uint8_t* buffer, uint32_t buffer_len, uint32_t* msg_len) {
  asn1::bit_ref bref(buffer, buffer_len);
  asn1::rrc::pcch_msg_s pcch_msg;

  // PCCH-MessageType 选择 c1，c1 中当前只有 paging 这个 choice。
  pcch_msg.msg.set_c1();

  // Paging 的几个主字段都是 OPTIONAL/presence-only；只置 ETWS 指示位即可完成编码。
  asn1::rrc::paging_s& paging = pcch_msg.msg.c1().paging();
  paging.etws_ind_present = true;

  if (pcch_msg.pack(bref) != SRSASN_SUCCESS) {
    return -1;
  }
  int len = bref.distance_bytes(buffer);
  srsran_vec_fprint_byte(stdout, buffer, len);
  *msg_len = len;
  return 0;
}


int gen_paging_imsi(uint8_t* buffer, uint32_t buffer_len, uint32_t* msg_len, uint8_t* imsi, uint32_t imsi_len) {
  asn1::bit_ref bref(buffer, buffer_len);
  asn1::rrc::pcch_msg_s pcch_msg;
  pcch_msg.msg.set_c1();
  asn1::rrc::paging_s& paging = pcch_msg.msg.c1().paging();
  paging.paging_record_list_present = true;
  paging_record_s paging_elem;
  paging_elem.ue_id.set_imsi(); // imsi_l, bounded_array
  memcpy(paging_elem.ue_id.imsi().data(), imsi, imsi_len);
  paging_elem.ue_id.imsi().resize(imsi_len);
  paging_elem.cn_domain = paging_record_s::cn_domain_e_::ps; // CN domain
  paging.paging_record_list.push_back(paging_elem);
  if (pcch_msg.pack(bref) != SRSASN_SUCCESS) {
    return -1;
  }
  int len = bref.distance_bytes(buffer);
  srsran_vec_fprint_byte(stdout, buffer, len);
  *msg_len = len;
  return 0;
}
int gen_attach_reject(uint8_t* buffer, uint32_t buffer_len, uint32_t* msg_len)
{
  // 1. 准备 RRC payload
  //const char* rrc_hex = "000800303a20b2f80828";
  const char* rrc_hex = "000800303a201af80828";
  //const char* rrc_hex = "0a00183a2078";
  size_t rrc_len = strlen(rrc_hex) / 2;
  // 2. 准备 MAC-I
  const size_t mac_len = 4;
  uint8_t mac[mac_len] = {0x00, 0x00, 0x00, 0x00};
  // 3. 构造 RLC Header（2字节）
  srsran::rlc_amd_pdu_header_t header = {};
  //data/control字段，表示当前pdu是数据还是控制信令
  header.dc  = srsran::RLC_DC_FIELD_DATA_PDU;
  //reversed flag
  header.rf  = 0;
  //poll，指示是否需要对当前RLC pdu进行确认
  header.p   = 1;
  //fragment information 指示是否被分段
  header.fi  = srsran::RLC_FI_FIELD_START_AND_END_ALIGNED;
  //sequence number 序列号
  header.sn  = 0;
  //长度指示器
  header.N_li = 0;
  // 4. 构造完整 SDU = RLC Header + RRC + MAC-I
  const size_t rlc_hdr_len = 2;
  const size_t total_len = rlc_hdr_len + rrc_len + mac_len;
  printf("rrc_len:%ld\n", rrc_len);
  uint8_t sdu[total_len];
  uint8_t* p = sdu;
  srsran::rlc_am_write_data_pdu_header(&header, &p);
  //hexdump(p, total_len);
  hex_string_to_byte_array(rrc_hex, p);
  p += rrc_len;
  //hexdump(p, total_len);
  memcpy(p, mac, mac_len);
  //hexdump(p, total_len);
  // 5. 创建 MAC PDU
  auto& mac_logger = srslog::fetch_basic_logger("MAC");
  const uint32_t mac_pdu_size = 22;
  srsran::byte_buffer_t pdu_buf;
  srsran::sch_pdu mac_msg_dl(mac_pdu_size, mac_logger);
  mac_msg_dl.init_tx(&pdu_buf, mac_pdu_size, true);
  // 6. 填入 SDU
  mac_msg_dl.new_subh();
  mac_msg_dl.get()->set_sdu(1, total_len, sdu);
  // 7. 写 PDU
  uint8_t* ptr = mac_msg_dl.write_packet(mac_logger);
  // 8. 拷贝结果
  uint32_t len = mac_msg_dl.get_pdu_len();
  if (buffer_len < len) {
    fprintf(stderr, "Buffer too small!\n");
    return -1;
  }
  memcpy(buffer, ptr, len);
  *msg_len = len;
  printf("==== MAC Attach Reject PDU ====\n");
  hexdump(ptr, len);
  printf("len:%d\n", len);

  return 0;
}

int gen_sib1_sysinfvaltag(uint8_t* buffer, uint32_t buffer_len, uint32_t* msg_len, uint8_t sys_info_value_tag) {
  uint8_t* rrc_msg = NULL;
  size_t rrc_msg_len = 0;
  if (read_hex_file_to_byte_array(sib1_path, &rrc_msg, &rrc_msg_len) != 0) {
      return -1;
  }
  if (rrc_msg_len == 0 || rrc_msg_len > buffer_len) {
      fprintf(stderr, "❌ Invalid message length: %zu\n", rrc_msg_len);
      free(rrc_msg);
      return -1;
  }
  //srsran_vec_fprint_byte(stdout, rrc_msg, rrc_msg_len);  
  cbit_ref bref(&rrc_msg[0], rrc_msg_len);
  bcch_dl_sch_msg_s bcch_msg;
  bcch_msg.unpack(bref);
  sib_type1_s& data = bcch_msg.msg.c1().sib_type1();
  data.sys_info_value_tag = sys_info_value_tag;
  data.sched_info_list.clear();
  sched_info_s sched_info_elem;
  sched_info_elem.si_periodicity = si_periodicity_r12_opts::rf8;
  sched_info_elem.sib_map_info.push_back(sib_type_e::sib_type3);
  data.sched_info_list.push_back(sched_info_elem);

  asn1::bit_ref bref_ret(buffer, buffer_len);
  if (bcch_msg.pack(bref_ret) != SRSRAN_SUCCESS) {
    ERROR("Error encoded sib1 message");
    return -1;
  }
  int len = bref_ret.distance_bytes(buffer);
  srsran_vec_fprint_byte(stdout, buffer, len);
  *msg_len = len;
  return 0;
}

int gen_sib1_tac(uint8_t* buffer, uint32_t buffer_len, uint32_t* msg_len, int tac) {
  uint8_t* rrc_msg = NULL;
  size_t rrc_msg_len = 0;
  if (read_hex_file_to_byte_array(sib1_path, &rrc_msg, &rrc_msg_len) != 0) {
      return -1;
  }
  if (rrc_msg_len == 0 || rrc_msg_len > buffer_len) {
      fprintf(stderr, "❌ Invalid message length: %zu\n", rrc_msg_len);
      free(rrc_msg);
      return -1;
  }
  //srsran_vec_fprint_byte(stdout, rrc_msg, rrc_msg_len);  
  cbit_ref bref(&rrc_msg[0], rrc_msg_len);
  bcch_dl_sch_msg_s bcch_msg;
  bcch_msg.unpack(bref);
  sib_type1_s& data = bcch_msg.msg.c1().sib_type1();
  data.cell_access_related_info.tac.from_number(tac);
  /*data.sched_info_list.clear();
  sched_info_s sched_info_elem;
  sched_info_elem.si_periodicity = si_periodicity_r12_opts::rf8;
  sched_info_elem.sib_map_info.push_back(sib_type_e::sib_type3);
  data.sched_info_list.push_back(sched_info_elem);*/
  asn1::bit_ref bref_ret(buffer, buffer_len);
  if (bcch_msg.pack(bref_ret) != SRSRAN_SUCCESS) {
    ERROR("Error encoded sib1 message");
    return -1;
  }
  int len = bref_ret.distance_bytes(buffer);
  srsran_vec_fprint_byte(stdout, buffer, len);
  json_writer js;
  static std::string sib1_json;
  data.to_json(js);
  sib1_json = js.to_string();
  std::cout << sib1_json << std::endl;
  *msg_len = len;
  return 0;
}
int gen_sib1_original(uint8_t* buffer, uint32_t buffer_len, uint32_t* msg_len) {
  uint8_t* rrc_msg = NULL;
  size_t rrc_msg_len = 0;

  if (read_hex_file_to_byte_array(sib1_path, &rrc_msg, &rrc_msg_len) != 0) {
      return -1;
  }
  if (rrc_msg_len == 0 || rrc_msg_len > buffer_len) {
      fprintf(stderr, "❌ Invalid message length: %zu\n", rrc_msg_len);
      free(rrc_msg);
      return -1;
  }
  //srsran_vec_fprint_byte(stdout, rrc_msg, rrc_msg_len);  
  cbit_ref bref(&rrc_msg[0], rrc_msg_len);
  bcch_dl_sch_msg_s bcch_msg;
  bcch_msg.unpack(bref);
  sib_type1_s& data = bcch_msg.msg.c1().sib_type1();
  asn1::bit_ref bref_ret(buffer, buffer_len);
  if (bcch_msg.pack(bref_ret) != SRSRAN_SUCCESS) {
    ERROR("Error encoded sib1 message");
    return -1;
  }
  int len = bref_ret.distance_bytes(buffer);
  srsran_vec_fprint_byte(stdout, buffer, len);
  *msg_len = len;
  return 0;
}

/**
 * @brief 生成声明 ETWS SIB10/SIB11 调度的 SIB1。
 *
 * 目标：让包含 SIB10/SIB11 的 SI message 的 SI window 起点落在子帧 1。
 *
 * LTE SI window 起点：
 *   x = (n - 1) * si-WindowLength
 *   SFN mod T = floor(x / 10)
 *   subframe  = x mod 10
 *
 * 这里设置 si-WindowLength = ms1，并把 SIB10/SIB11 放在 schedulingInfoList 第 2 项：
 *   n = 2, x = 1ms, subframe = 1
 *
 * 注意：SIB2 固定在第 1 个 SI message 中，schedulingInfoList 第 1 项的
 * mappingInfo 表示除 SIB2 外一起放入该 SI message 的其它 SIB。这里保留
 * 原第 1 项，再把 sibType10 和 sibType11 插入第 2 项，使其跟 SF1 对齐。
 */
int gen_sib1_etws_sched(uint8_t* buffer, uint32_t buffer_len, uint32_t* msg_len)
{
  uint8_t* rrc_msg = NULL;
  size_t   rrc_msg_len = 0;

  if (read_hex_file_to_byte_array(sib1_path, &rrc_msg, &rrc_msg_len) != 0) {
    return -1;
  }
  if (rrc_msg_len == 0 || rrc_msg_len > buffer_len) {
    fprintf(stderr, "❌ Invalid message length: %zu\n", rrc_msg_len);
    free(rrc_msg);
    return -1;
  }

  cbit_ref bref(&rrc_msg[0], rrc_msg_len);
  bcch_dl_sch_msg_s bcch_msg;
  bcch_msg.unpack(bref);
  free(rrc_msg);

  sib_type1_s& sib1 = bcch_msg.msg.c1().sib_type1();


  sib1.si_win_len = sib_type1_s::si_win_len_e_::ms40;
  sib1.sys_info_value_tag = 1;
  sib1.sched_info_list.clear();

  sched_info_s sib3;
  sib3.si_periodicity = si_periodicity_r12_opts::rf16;
  sib3.sib_map_info.push_back(sib_type_e::sib_type3);
  sib1.sched_info_list.push_back(sib3);
  
  sched_info_s etws_sched;
  etws_sched.si_periodicity = si_periodicity_r12_opts::rf16;
  etws_sched.sib_map_info.push_back(sib_type_e::sib_type10);
  etws_sched.sib_map_info.push_back(sib_type_e::sib_type11);
  sib1.sched_info_list.push_back(etws_sched);

  asn1::bit_ref bref_ret(buffer, buffer_len);
  if (bcch_msg.pack(bref_ret) != SRSASN_SUCCESS) {
    ERROR("Error encoded SIB1 ETWS scheduling message");
    return -1;
  }

  int len = bref_ret.distance_bytes(buffer);
  srsran_vec_fprint_byte(stdout, buffer, len);

  json_writer js;
  static std::string sib1_json;
  sib1.to_json(js);
  sib1_json = js.to_string();
  std::cout << sib1_json << std::endl;

  *msg_len = len;
  return 0;
}

int gen_sib2_acbarring(uint8_t* buffer, uint32_t buffer_len, uint32_t* msg_len) {
  uint8_t* rrc_msg = NULL;
  size_t rrc_msg_len = 0;
  if (read_hex_file_to_byte_array(sib2_path, &rrc_msg, &rrc_msg_len) != 0) {
      return -1;
  }
  if (rrc_msg_len == 0 || rrc_msg_len > buffer_len) {
      fprintf(stderr, "❌ Invalid message length: %zu\n", rrc_msg_len);
      free(rrc_msg);
      return -1;
  }
  srsran_vec_fprint_byte(stdout, rrc_msg, rrc_msg_len);  

  cbit_ref bref(&rrc_msg[0], rrc_msg_len);
  bcch_dl_sch_msg_s bcch_msg;
  bcch_msg.unpack(bref);
  sys_info_s::crit_exts_c_* sinfo = &bcch_msg.msg.c1().sys_info().crit_exts;
  sys_info_r8_ies_s& sys_r8 = sinfo->sys_info_r8();
  sib_type2_s* sib2 = &(sys_r8.sib_type_and_info[0].sib2());
  sib2->ac_barr_info_present = true;
  sib2->ac_barr_info.ac_barr_for_emergency = true;
  sib2->ac_barr_info.ac_barr_for_mo_sig_present = true;
  sib2->ac_barr_info.ac_barr_for_mo_sig.ac_barr_factor = ac_barr_cfg_s::ac_barr_factor_opts::p00;
  sib2->ac_barr_info.ac_barr_for_mo_sig.ac_barr_time = ac_barr_cfg_s::ac_barr_time_opts::s512;
  sib2->ac_barr_info.ac_barr_for_mo_sig.ac_barr_for_special_ac.from_number(31);
  sib2->ac_barr_info.ac_barr_for_mo_data_present = true;
  sib2->ac_barr_info.ac_barr_for_mo_data.ac_barr_factor = ac_barr_cfg_s::ac_barr_factor_opts::p00;
  sib2->ac_barr_info.ac_barr_for_mo_data.ac_barr_time = ac_barr_cfg_s::ac_barr_time_opts::s512;
  sib2->ac_barr_info.ac_barr_for_mo_data.ac_barr_for_special_ac.from_number(31);
  asn1::bit_ref bref_ret(buffer, buffer_len);
  if (bcch_msg.pack(bref_ret) != SRSRAN_SUCCESS) {
    ERROR("Error encoded sib2 message");
    return -1;
  }
  int len = bref_ret.distance_bytes(buffer);
  srsran_vec_fprint_byte(stdout, buffer, len);  
  json_writer js;
  static std::string sib2_json;
  sib2->to_json(js);
  sib2_json = js.to_string();
  std::cout << sib2_json << std::endl;
  *msg_len = len;
  return 0;
}

// ETWS 示例内容。Paging 只携带 etws-Indication，真正的 ETWS primary/secondary
// notification 放在 SIB10/SIB11 中，并通过相同 messageIdentifier/serialNumber 关联。
static const uint16_t ETWS_MSG_ID_EARTHQUAKE_AND_TSUNAMI = 0x1102;
static const uint16_t ETWS_SERIAL_NUM_DEFAULT             = 0x3000;
static const uint8_t  ETWS_CBS_PAGE_SIZE                  = 82;

static size_t pack_gsm7_default_alphabet(const char* text, uint8_t* out, size_t out_len)
{
  memset(out, 0, out_len);

  const size_t text_len = strlen(text);
  for (size_t i = 0; i < text_len; ++i) {
    // 本示例只使用 GSM 7-bit default alphabet 中与 ASCII 编码相同的字符。
    const uint8_t septet     = static_cast<uint8_t>(text[i]) & 0x7f;
    const size_t  bit_offset = i * 7;
    const size_t  byte_idx   = bit_offset / 8;
    const uint8_t bit_shift  = bit_offset % 8;

    if (byte_idx >= out_len) {
      break;
    }
    out[byte_idx] |= septet << bit_shift;
    if (bit_shift > 1 && byte_idx + 1 < out_len) {
      out[byte_idx + 1] |= septet >> (8 - bit_shift);
    }
  }

  return (text_len * 7 + 7) / 8;
}

static void fill_cbs_warning_msg_contents(dyn_octstring& warning_msg_segment, const char* warning_text)
{
  uint8_t encoded_page[ETWS_CBS_PAGE_SIZE] = {};
  size_t  encoded_len = pack_gsm7_default_alphabet(warning_text, encoded_page, sizeof(encoded_page));
  if (encoded_len > ETWS_CBS_PAGE_SIZE) {
    encoded_len = ETWS_CBS_PAGE_SIZE;
  }

  // CBS Warning Message Contents:
  //   Number-of-Pages(1) + repeated { CBS-Message-Information-Page(82) + CBS-Message-Information-Length(1) }.
  // 这里构造单页完整消息，因此 Number-of-Pages=1，SIB11 的 segmentType 也设置为 lastSegment。
  warning_msg_segment.resize(1 + ETWS_CBS_PAGE_SIZE + 1);
  warning_msg_segment[0] = 1;
  memcpy(&warning_msg_segment[1], encoded_page, ETWS_CBS_PAGE_SIZE);
  warning_msg_segment[1 + ETWS_CBS_PAGE_SIZE] = static_cast<uint8_t>(encoded_len);
}

/**
 * @brief 填充 SIB10：ETWS Primary Notification。
 *
 * SIB10 承载 ETWS 的快速告警信息：
 * - messageIdentifier：告警类别。0x1102 表示 earthquake and tsunami warning。
 * - serialNumber：告警实例编号。UE 用它判断是否是新的/更新的告警。
 * - warningType：2 字节 ETWS warning type。这里使用 earthquake and tsunami，并置 emergency user alert/popup。
 *
 * 注意：SIB10 不承载 warning text，文字内容在 SIB11 的 warningMessageSegment 中。
 */
static void fill_etws_sib10(sib_type10_s& sib10)
{
  sib10.ext           = false;
  sib10.dummy_present = false;
  sib10.msg_id.from_number(ETWS_MSG_ID_EARTHQUAKE_AND_TSUNAMI, 16);
  sib10.serial_num.from_number(ETWS_SERIAL_NUM_DEFAULT, 16);
  sib10.warning_type.from_number(0x0580);
}

/**
 * @brief 填充 SIB11：ETWS Secondary Notification。
 *
 * SIB11 承载完整的 ETWS 文字内容。这里构造单分段消息：
 * - warningMessageSegmentType = lastSegment，表示这是最后一段。
 * - warningMessageSegmentNumber = 0，第一段也是唯一一段。
 * - dataCodingScheme = 0x0F，表示按 GSM 7-bit default alphabet 解释该段内容。
 * - warningMessageSegment 按 CBS Warning Message Contents 封装：
 *   Number-of-Pages(1) + CBS-Message-Information-Page(82) + CBS-Message-Information-Length(1)。
 *
 * 若要发送更长文本，可以把 warningMessageSegment 拆成多段：前面的段使用
 * notLastSegment，最后一段使用 lastSegment，并递增 warningMessageSegmentNumber。
 */
static void fill_etws_sib11(sib_type11_s& sib11)
{
  const char* warning_text =
      "ETWS TEST: EARTHQUAKE AND TSUNAMI WARNING. MOVE TO HIGHER GROUND NOW.";

  sib11.ext                        = false;
  sib11.data_coding_scheme_present = true;
  sib11.msg_id.from_number(ETWS_MSG_ID_EARTHQUAKE_AND_TSUNAMI, 16);
  sib11.serial_num.from_number(ETWS_SERIAL_NUM_DEFAULT, 16);
  sib11.warning_msg_segment_type = sib_type11_s::warning_msg_segment_type_e_::last_segment;
  sib11.warning_msg_segment_num  = 0;
  fill_cbs_warning_msg_contents(sib11.warning_msg_segment, warning_text);
  sib11.data_coding_scheme.from_number(0x0f);
}

static int pack_etws_sys_info(uint8_t* buffer, uint32_t buffer_len, uint32_t* msg_len, bool include_sib10, bool include_sib11)
{
  bcch_dl_sch_msg_s bcch_msg;
  bcch_msg.msg.set_c1();

  sys_info_s&        sys_info = bcch_msg.msg.c1().set_sys_info();
  sys_info_r8_ies_s& sys_r8   = sys_info.crit_exts.set_sys_info_r8();
  sys_r8.non_crit_ext_present = false;
  sys_r8.sib_type_and_info.clear();

  if (include_sib10) {
    sys_info_r8_ies_s::sib_type_and_info_item_c_ item;
    sib_type10_s& sib10 = item.set_sib10();
    fill_etws_sib10(sib10);
    sys_r8.sib_type_and_info.push_back(item);
  }

  if (include_sib11) {
    sys_info_r8_ies_s::sib_type_and_info_item_c_ item;
    sib_type11_s& sib11 = item.set_sib11();
    fill_etws_sib11(sib11);
    sys_r8.sib_type_and_info.push_back(item);
  }

  asn1::bit_ref bref(buffer, buffer_len);
  if (bcch_msg.pack(bref) != SRSASN_SUCCESS) {
    ERROR("Error encoded ETWS system information message");
    return -1;
  }

  int len = bref.distance_bytes(buffer);
  srsran_vec_fprint_byte(stdout, buffer, len);

  json_writer js;
  sys_info.to_json(js);
  std::cout << js.to_string() << std::endl;

  *msg_len = len;
  return 0;
}

int gen_sib10_etws(uint8_t* buffer, uint32_t buffer_len, uint32_t* msg_len)
{
  return pack_etws_sys_info(buffer, buffer_len, msg_len, true, false);
}

int gen_sib11_etws(uint8_t* buffer, uint32_t buffer_len, uint32_t* msg_len)
{
  return pack_etws_sys_info(buffer, buffer_len, msg_len, false, true);
}

int gen_sib10_sib11_etws(uint8_t* buffer, uint32_t buffer_len, uint32_t* msg_len)
{
  return pack_etws_sys_info(buffer, buffer_len, msg_len, true, true);
}


int gen_identity_request(uint8_t* buffer, uint32_t buffer_len, uint32_t* msg_len) {
  const char *rrc_hex = "000800183aa80800000000";
  //const char* rrc_hex = "0a00183a2078";
  size_t rrc_len = strlen(rrc_hex) / 2;
  // 2. 准备 MAC-I
  const size_t mac_len = 4;
  uint8_t mac[mac_len] = {0x00, 0x00, 0x00, 0x00};
  // 3. 构造 RLC Header（2字节）
  srsran::rlc_amd_pdu_header_t header = {};
  //data/control字段，表示当前pdu是数据还是控制信令
  header.dc  = srsran::RLC_DC_FIELD_DATA_PDU;
  //reversed flag
  header.rf  = 0;
  //poll，指示是否需要对当前RLC pdu进行确认
  header.p   = 0;
  //fragment information 指示是否被分段
  header.fi  = srsran::RLC_FI_FIELD_START_AND_END_ALIGNED;
  //sequence number 序列号
  header.sn  = 0;
  //长度指示器
  header.N_li = 0;
  // 4. 构造完整 SDU = RLC Header + RRC + MAC-I
  const size_t rlc_hdr_len = 2;
  const size_t total_len = rlc_hdr_len + rrc_len + mac_len;
  printf("rrc_len:%ld\n", rrc_len);
  uint8_t sdu[total_len];
  uint8_t* p = sdu;
  srsran::rlc_am_write_data_pdu_header(&header, &p);
  //hexdump(p, total_len);
  hex_string_to_byte_array(rrc_hex, p);
  p += rrc_len;
  //hexdump(p, total_len);
  memcpy(p, mac, mac_len);
  //hexdump(p, total_len);
  // 5. 创建 MAC PDU
  auto& mac_logger = srslog::fetch_basic_logger("MAC");
  const uint32_t mac_pdu_size = 22;
  srsran::byte_buffer_t pdu_buf;
  srsran::sch_pdu mac_msg_dl(mac_pdu_size, mac_logger);
  mac_msg_dl.init_tx(&pdu_buf, mac_pdu_size, true);
  // 6. 填入 SDU
  mac_msg_dl.new_subh();
  mac_msg_dl.get()->set_sdu(1, total_len, sdu);
  // 7. 写 PDU
  uint8_t* ptr = mac_msg_dl.write_packet(mac_logger);
  // 8. 拷贝结果
  uint32_t len = mac_msg_dl.get_pdu_len();
  if (buffer_len < len) {
    fprintf(stderr, "Buffer too small!\n");
    return -1;
  }
  memcpy(buffer, ptr, len);
  *msg_len = len;
  printf("==== MAC identity request PDU ====\n");
  hexdump(ptr, len);
  printf("len:%d\n", len);
  return 0;
}

int gen_rar_pdu(uint32_t preamble, uint8_t* buffer, uint32_t buffer_len, uint32_t* msg_len) {
  // Prepare RAR grant
  uint32_t buffer_size = 8;
  uint8_t grant_buffer[64] = {};
  srsran_dci_rar_grant_t rar_grant        = {};
  //资源块分配 用一个编号表示UE可以在哪些PRB上传输数据 根据fixed size resource allocation方式编码
  rar_grant.rba = 202;
  rar_grant.cqi_request = 0;
  //是否要求进行跳频传输
  rar_grant.hopping_flag = 0;
  //截断的mcs调制编码方案
  rar_grant.trunc_mcs = 0;
  //是否要求增加上行发送延时
  rar_grant.ul_delay = 0;
  //功率控制命令，告诉UE是否调整上行发射功率
  rar_grant.tpc_pusch = 3;
  srsran_dci_rar_pack(&rar_grant, grant_buffer);

  // Create MAC PDU and add RAR subheader
  srsran::rar_pdu rar_pdu;

  srsran::byte_buffer_t tx_buffer;
  rar_pdu.init_tx(&tx_buffer, buffer_size);
  uint32_t ta_cmd = 0;
  uint32_t t_crnti = 272;

  if (rar_pdu.new_subh()) {
    //前导码
    rar_pdu.get()->set_rapid(preamble);
    rar_pdu.get()->set_ta_cmd(ta_cmd);
    //分配的crnti
    rar_pdu.get()->set_temp_crnti(t_crnti);
    rar_pdu.get()->set_sched_grant(grant_buffer);
  }
  rar_pdu.write_packet(tx_buffer.msg);
  hexdump(tx_buffer.msg, size_t(buffer_size));

  memcpy(buffer, tx_buffer.msg, size_t(buffer_size));  // 复制数据到buffer
  //*msg_len = tx_buffer.N_bytes;                      // 返回数据长度
  *msg_len = buffer_size;
  /*msg_len = buffer_size;                      // 返回数据长度
  printf("msg len:%u \n", *msg_len);
  */
  hexdump(buffer, size_t(buffer_size));
  return 0;
}


void gen_pdn_connectivity_reject(LIBLTE_BYTE_MSG_STRUCT* msg)
{
  LIBLTE_MME_PDN_CONNECTIVITY_REJECT_MSG_STRUCT pdn_con_reject = {};
  pdn_con_reject.eps_bearer_id                                 = 0x0;
  pdn_con_reject.proc_transaction_id                           = 0x1;
  pdn_con_reject.esm_cause                                     = LIBLTE_MME_ESM_CAUSE_SERVICE_OPTION_NOT_SUPPORTED;
  
  liblte_mme_pack_pdn_connectivity_reject_msg(&pdn_con_reject, msg);
}

void gen_attach_reject_nas_pdu(srsran::unique_byte_buffer_t& msg)
{
  LIBLTE_MME_ATTACH_REJECT_MSG_STRUCT attach_reject;
  bzero(&attach_reject, sizeof(LIBLTE_MME_ATTACH_REJECT_MSG_STRUCT));
  attach_reject.emm_cause =LIBLTE_MME_EMM_CAUSE_ILLEGAL_UE;
  //attach_reject.emm_cause = LIBLTE_MME_EMM_CAUSE_CONGESTION;
  printf("attach_reject.emm_cause = %d\n", attach_reject.emm_cause);
  attach_reject.t3446_value_present = true;
  attach_reject.t3446_value = 0x5;
  gen_pdn_connectivity_reject(&attach_reject.esm_msg);
  liblte_mme_pack_attach_reject_msg(&attach_reject, (LIBLTE_BYTE_MSG_STRUCT*)msg.get());
}

void uint16_to_uint8(uint16_t i, uint8_t* buf)
{
  buf[0] = (i >> 8) & 0xFF;
  buf[1] = i & 0xFF;
}

void uint24_to_uint8(uint32_t i, uint8_t* buf)
{
  buf[0] = (i >> 16) & 0xFF;
  buf[1] = (i >> 8) & 0xFF;
  buf[2] = i & 0xFF;
}

using namespace srsran;
void write_data_header(const srsran::unique_byte_buffer_t& sdu, uint32_t count)
{
  uint8_t hdr_len_bytes = 1;
  uint8_t sn_len = 5;

  if (hdr_len_bytes > sdu->get_headroom()) {
    return;
  }
  sdu->msg -= hdr_len_bytes;
  sdu->N_bytes += hdr_len_bytes;

  switch (sn_len) {
    case PDCP_SN_LEN_5:
      sdu->msg[0] = SN(count); 
      break;
    case PDCP_SN_LEN_7:
      sdu->msg[0] = SN(count);
      

      break;
    case PDCP_SN_LEN_12:
      uint16_to_uint8(SN(count), sdu->msg);

      break;
    case PDCP_SN_LEN_18:
      uint24_to_uint8(SN(count), sdu->msg);
      sdu->msg[0] |= 0x80; 
      break;
    default:
      printf("error\n");
  }
}


void gen_attach_reject_pdu_v1(uint8_t* buffer, uint32_t buffer_len, uint32_t* msg_len)
{
  srsran::unique_byte_buffer_t nas_tx = srsran::make_byte_buffer();
  gen_attach_reject_nas_pdu(nas_tx);
  printf("NAS Message (%d bytes): ", nas_tx->N_bytes);
  for (uint32_t i = 0; i < nas_tx->N_bytes; ++i) {
    printf("%02x ", nas_tx->msg[i]);
  }
  printf("\n");
  dl_dcch_msg_s dl_dcch_msg;
  dl_dcch_msg.msg.set_c1();
  dl_dcch_msg_type_c::c1_c_* msg_c1 = &dl_dcch_msg.msg.c1();
  dl_info_transfer_r8_ies_s* dl_info_r8 =
      &msg_c1->set_dl_info_transfer().crit_exts.set_c1().set_dl_info_transfer_r8();
  //    msg_c1->dl_info_transfer().rrc_transaction_id = ;
  dl_info_r8->non_crit_ext_present = false;
  dl_info_r8->ded_info_type.set_ded_info_nas();
  dl_info_r8->ded_info_type.ded_info_nas().resize(nas_tx->N_bytes);
  memcpy(msg_c1->dl_info_transfer().crit_exts.c1().dl_info_transfer_r8().ded_info_type.ded_info_nas().data(),
  nas_tx->msg,
  nas_tx->N_bytes);
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

  write_data_header(pdu, 0);
 printf("PDCP Message (%d bytes): ", pdu->N_bytes);
  for (uint32_t i = 0; i < pdu->N_bytes; ++i) {
    printf("%02x ", pdu->msg[i]);
  }
  printf("\n");

  const size_t mac_len = 4;
  uint8_t mac[mac_len] = {0x00, 0x00, 0x00, 0x00};
  append_mac(pdu, mac);
  const size_t rlc_hdr_len = 2;
  const size_t rrc_len = pdu->N_bytes;
  const size_t rlc_sdu_len = rlc_hdr_len + rrc_len;

  uint8_t sdu[rlc_sdu_len];
  uint8_t* p = sdu;
  srsran::rlc_amd_pdu_header_t header = {};
  header.dc  = srsran::RLC_DC_FIELD_DATA_PDU;
  header.rf  = 0;
  header.p   = 1;
  header.fi  = srsran::RLC_FI_FIELD_START_AND_END_ALIGNED;
  header.sn  = 0;
  header.N_li = 0;
  srsran::rlc_am_write_data_pdu_header(&header, &p);
  memcpy(p, pdu->msg, rrc_len);
  p += rrc_len;
  
  printf("RLC Message (%zu bytes): ", rlc_sdu_len);
  for (size_t i = 0; i < rlc_sdu_len; ++i) {
      printf("%02x ", sdu[i]);
  }
  printf("\n");
  auto& mac_logger = srslog::fetch_basic_logger("MAC");
  uint32_t mac_subheader_len = 1;
  if (rlc_sdu_len >= 128) {
      mac_subheader_len = 2;
  }
  uint32_t required_mac_pdu_size = mac_subheader_len + rlc_sdu_len;

  srsran::byte_buffer_t pdu_buf;
  srsran::sch_pdu mac_msg_dl(required_mac_pdu_size, mac_logger);
  mac_msg_dl.init_tx(&pdu_buf, required_mac_pdu_size, true);
  mac_msg_dl.new_subh();
  mac_msg_dl.get()->set_sdu(1, rlc_sdu_len, sdu);
  uint8_t* ptr = mac_msg_dl.write_packet(mac_logger);
  uint32_t len = mac_msg_dl.get_pdu_len();
  if (pdu->capacity() < len) {
    printf("Buffer too small to store the generated PDU\n");
    return;
  }
  memcpy(pdu->msg, ptr, len);
  pdu->N_bytes = len;
  std::cout<< pdu->data() << std::endl;
  memcpy(buffer, ptr, len);
  *msg_len = len;
  printf("==== MAC Attach Reject PDU (%d bytes) ====\n", len);
  hexdump(ptr, len);
}

void gen_attach_accept_nas_pdu(srsran::unique_byte_buffer_t& msg)
{
  const char* nas_hex = "0742013e060000f1100007001d5201c10107070673727361706e0501ac100002270880000d0408080808500bf600f11000011a791571281300f1";
  hex_string_to_byte_array(nas_hex, msg->msg);
  msg->N_bytes = strlen(nas_hex) / 2;
}
void gen_attach_accept_pdu(uint8_t* buffer, uint32_t buffer_len, uint32_t* msg_len)
{
  srsran::unique_byte_buffer_t nas_tx = srsran::make_byte_buffer();
  gen_attach_accept_nas_pdu(nas_tx);
  printf("NAS Message (%d bytes): ", nas_tx->N_bytes);
  for (uint32_t i = 0; i < nas_tx->N_bytes; ++i) {
    printf("%02x ", nas_tx->msg[i]);
  }
  printf("\n");
  dl_dcch_msg_s dl_dcch_msg;
  dl_dcch_msg.msg.set_c1();
  dl_dcch_msg_type_c::c1_c_* msg_c1 = &dl_dcch_msg.msg.c1();


  dl_info_transfer_r8_ies_s* dl_info_r8 =
      &msg_c1->set_dl_info_transfer().crit_exts.set_c1().set_dl_info_transfer_r8();
  //    msg_c1->dl_info_transfer().rrc_transaction_id = ;
  dl_info_r8->non_crit_ext_present = false;
  dl_info_r8->ded_info_type.set_ded_info_nas();
  dl_info_r8->ded_info_type.ded_info_nas().resize(nas_tx->N_bytes);
  memcpy(msg_c1->dl_info_transfer().crit_exts.c1().dl_info_transfer_r8().ded_info_type.ded_info_nas().data(),
  nas_tx->msg,
  nas_tx->N_bytes);
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

  write_data_header(pdu, 0);
  printf("PDCP Message (%d bytes): ", pdu->N_bytes);
  for (uint32_t i = 0; i < pdu->N_bytes; ++i) {
    printf("%02x ", pdu->msg[i]);
  }
  printf("\n");
  const size_t mac_len = 4;
  uint8_t mac[mac_len] = {0x00, 0x00, 0x00, 0x00};
  append_mac(pdu, mac);
  const size_t rlc_hdr_len = 2;
  const size_t rrc_len = pdu->N_bytes;
  const size_t rlc_sdu_len = rlc_hdr_len + rrc_len; 
  uint8_t sdu[rlc_sdu_len];
  uint8_t* p = sdu;
  srsran::rlc_amd_pdu_header_t header = {};
  header.dc  = srsran::RLC_DC_FIELD_DATA_PDU;
  header.rf  = 0;
  header.p   = 1;
  header.fi  = srsran::RLC_FI_FIELD_START_AND_END_ALIGNED;
  header.sn  = 0;
  header.N_li = 0;
  srsran::rlc_am_write_data_pdu_header(&header, &p);
  memcpy(p, pdu->msg, rrc_len);
  p += rrc_len;
  printf("RLC Message (%zu bytes): ", rlc_sdu_len);
  for (size_t i = 0; i < rlc_sdu_len; ++i) {
      printf("%02x ", sdu[i]);
  }
  printf("\n");
  auto& mac_logger = srslog::fetch_basic_logger("MAC");
  uint32_t mac_subheader_len = 1;
  if (rlc_sdu_len >= 128) {
      mac_subheader_len = 2;
  }
  uint32_t required_mac_pdu_size = mac_subheader_len + rlc_sdu_len;
  srsran::byte_buffer_t pdu_buf;
  srsran::sch_pdu mac_msg_dl(required_mac_pdu_size, mac_logger);
  mac_msg_dl.init_tx(&pdu_buf, required_mac_pdu_size, true);
  mac_msg_dl.new_subh();
  mac_msg_dl.get()->set_sdu(1, rlc_sdu_len, sdu);
  uint8_t* ptr = mac_msg_dl.write_packet(mac_logger);
  uint32_t len = mac_msg_dl.get_pdu_len();
  if (pdu->capacity() < len) {
    printf("Buffer too small to store the generated PDU\n");
    return;
  }
  memcpy(pdu->msg, ptr, len);
  pdu->N_bytes = len;
  std::cout<< pdu->data() << std::endl;
  memcpy(buffer, ptr, len);
  *msg_len = len;
  printf("==== MAC Attach Accept PDU (%d bytes) ====\n", len);
  hexdump(ptr, len);
}
