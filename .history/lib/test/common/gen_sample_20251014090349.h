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
#include "log.h"


using namespace asn1;
using namespace asn1::rrc;

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
void hexdump(uint8_t* data, size_t length) {
  for (size_t i = 0; i < length; i += 16) {
      printf("%08zx: ", i);
      for (size_t j = 0; j < 16 && (i + j) < length; ++j) {
          printf("%02X ", data[i + j]);
      }
      printf("\n");
  }
  for (size_t i = 0; i < length; i += 16) {
    printf("%08zx: ", i);
    for (size_t j = 0; j < 16 && (i + j) < length; ++j) {
        printf("%02X", data[i + j]);
    }
    printf("\n");
}
}
int append_mac(uint8_t* buffer, size_t buffer_len, size_t current_len, const uint8_t mac[4], size_t* new_len)
{
  const size_t mac_len = 4;
  if (current_len + mac_len > buffer_len) {
    fprintf(stderr, "Not enough space to append MAC-I\n");
    return -1;
  }
  memcpy(buffer + current_len, mac, mac_len);
  *new_len = current_len + mac_len;
  return 0;
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

  // 打印 PUSCH 配置
  printf("  pusch_cfg_common:\n");
  printf("    pusch_cfg_basic:\n");
  printf("      n_sb: %u\n", rr_cfg_common.pusch_cfg_common.pusch_cfg_basic.n_sb);
  printf("      hop_mode: %s\n", rr_cfg_common.pusch_cfg_common.pusch_cfg_basic.hop_mode.to_string());
  printf("      pusch_hop_offset: %u\n", rr_cfg_common.pusch_cfg_common.pusch_cfg_basic.pusch_hop_offset);
  printf("      enable64_qam: %s\n", rr_cfg_common.pusch_cfg_common.pusch_cfg_basic.enable64_qam ? "true" : "false");

  // 打印 PUCCH 配置
  printf("  pucch_cfg_common:\n");
  printf("    delta_pucch_shift: %s\n", rr_cfg_common.pucch_cfg_common.delta_pucch_shift.to_string());
  printf("    nrb_cqi: %u\n", rr_cfg_common.pucch_cfg_common.nrb_cqi);
  printf("    ncs_an: %u\n", rr_cfg_common.pucch_cfg_common.ncs_an);
  printf("    n1_pucch_an: %u\n", rr_cfg_common.pucch_cfg_common.n1_pucch_an);

  // 打印 SRS UL 配置
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

  // 打印 UL 功率控制配置
  printf("  ul_pwr_ctrl_common:\n");
  printf("    p0_nominal_pusch: %d dBm\n", rr_cfg_common.ul_pwr_ctrl_common.p0_nominal_pusch);
  printf("    alpha: %s\n", rr_cfg_common.ul_pwr_ctrl_common.alpha.to_string());
  printf("    p0_nominal_pucch: %d dBm\n", rr_cfg_common.ul_pwr_ctrl_common.p0_nominal_pucch);
  printf("    delta_preamb_msg3: %d dB\n", rr_cfg_common.ul_pwr_ctrl_common.delta_preamb_msg3);

  // 打印 UL 循环前缀长度
  printf("  ul_cp_len: %s\n", rr_cfg_common.ul_cp_len.to_string());


}

int print_sib2_fields(const sib_type2_s& verified_data) {
  // Print selected SIB2 message fields
  printf("SIB2 Message Fields:\n");
  printf("ext: %s\n", verified_data.ext ? "true" : "false");
  printf("ac_barr_info_present: %s\n", verified_data.ac_barr_info_present ? "true" : "false");
  printf("mbsfn_sf_cfg_list_present: %s\n", verified_data.mbsfn_sf_cfg_list_present ? "true" : "false");

  // Access Barring Information
  printf("ac_barr_info:\n");
  printf("  ac_barr_for_mo_sig_present: %s\n", verified_data.ac_barr_info.ac_barr_for_mo_sig_present ? "true" : "false");
  printf("  ac_barr_for_mo_data_present: %s\n", verified_data.ac_barr_info.ac_barr_for_mo_data_present ? "true" : "false");
  printf("  ac_barr_for_emergency: %s\n", verified_data.ac_barr_info.ac_barr_for_emergency ? "true" : "false");

  // Print details of ac_barr_for_mo_sig if present
  if (verified_data.ac_barr_info.ac_barr_for_mo_sig_present) {
      printf("  ac_barr_for_mo_sig:\n");
      printf("    ac_barr_factor: %s\n", verified_data.ac_barr_info.ac_barr_for_mo_sig.ac_barr_factor.to_string());
      printf("    ac_barr_time: %s\n", verified_data.ac_barr_info.ac_barr_for_mo_sig.ac_barr_time.to_string());
      printf("    ac_barr_for_special_ac: %s\n", verified_data.ac_barr_info.ac_barr_for_mo_sig.ac_barr_for_special_ac.to_string().c_str());
  }

  // Print details of ac_barr_for_mo_data if present
  if (verified_data.ac_barr_info.ac_barr_for_mo_data_present) {
      printf("  ac_barr_for_mo_data:\n");
      printf("    ac_barr_factor: %s\n", verified_data.ac_barr_info.ac_barr_for_mo_data.ac_barr_factor.to_string());
      printf("    ac_barr_time: %s\n", verified_data.ac_barr_info.ac_barr_for_mo_data.ac_barr_time.to_string());
      printf("    ac_barr_for_special_ac: %s\n", verified_data.ac_barr_info.ac_barr_for_mo_data.ac_barr_for_special_ac.to_string().c_str());
  }

  // Radio Resource Config Common SIB
  printf("rr_cfg_common:\n");
  print_rr_cfg_common(verified_data.rr_cfg_common);

  // UE Timers and Constants
  printf("ue_timers_and_consts:\n");
  // Print specific fields from ue_timers_and_consts as needed
  // e.g., printf("  t300: %u\n", verified_data.ue_timers_and_consts.t300);
  // Frequency Information
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


  // MBSFN Subframe Config List
  printf("mbsfn_sf_cfg_list:\n");
  // Optionally, print details of mbsfn_sf_cfg_list

  // Time Alignment Timer
  //printf("time_align_timer_common: %u\n", verified_data.time_align_timer_common);

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

  // 获取文件大小
  fseek(fp, 0, SEEK_END);
  long file_size = ftell(fp);
  fseek(fp, 0, SEEK_SET);

  if (file_size == 0) {
      fprintf(stderr, "❌ Error: File '%s' is empty\n", filename);
      fclose(fp);
      return -1;
  }

  // 分配内存读取整个文件
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

  // 检查是否为有效的十六进制字符串（可选，增强健壮性）
  for (int i = 0; i < file_size; i++) {
      if (!isxdigit((unsigned char)hex_str[i])) {
          fprintf(stderr, "❌ Error: Invalid hex character in file '%s'\n", filename);
          free(hex_str);
          return -1;
      }
  }

  // 必须是偶数长度
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

  // 转换 hex 字符对为字节
  for (size_t i = 0; i < len; i++) {
      sscanf(hex_str + 2*i, "%2hhx", &data[i]);
  }

  free(hex_str);

  // 输出结果
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
  const char *rrc_msg_hex_stream = "40d18023a300063046cca38050300221020898870786";
  size_t byte_array_length = strlen(rrc_msg_hex_stream) / 2;
  uint8_t rrc_msg[byte_array_length];
  hex_string_to_byte_array(rrc_msg_hex_stream, rrc_msg);
  uint32_t rrc_msg_len = sizeof(rrc_msg);
  cbit_ref bref(&rrc_msg[0], sizeof(rrc_msg));
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
/*
int gen_sib1_tac(uint8_t* buffer, uint32_t buffer_len, uint32_t* msg_len, int tac) {
  const char *rrc_msg_hex_stream = "48d18023a300063046cca38050300221020898478702a49501806000";
  size_t byte_array_length = strlen(rrc_msg_hex_stream) / 2;
  uint8_t rrc_msg[byte_array_length];
  hex_string_to_byte_array(rrc_msg_hex_stream, rrc_msg);
  uint32_t rrc_msg_len = sizeof(rrc_msg);
  cbit_ref bref(&rrc_msg[0], sizeof(rrc_msg));
  bcch_dl_sch_msg_s bcch_msg;
  bcch_msg.unpack(bref);
  sib_type1_s& data = bcch_msg.msg.c1().sib_type1();
  data.cell_access_related_info.tac.from_number(tac);
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
*/
int gen_sib1_tac(uint8_t* buffer, uint32_t buffer_len, uint32_t* msg_len, int tac) {
  uint8_t* rrc_msg = NULL;
  size_t rrc_msg_len = 0;
  if (read_hex_file_to_byte_array("../output/sib1.hex", &rrc_msg, &rrc_msg_len) != 0) {
      return -1;
  }
  if (rrc_msg_len == 0 || rrc_msg_len > buffer_len) {
      fprintf(stderr, "❌ Invalid message length: %zu\n", rrc_msg_len);
      free(rrc_msg);
      return -1;
  }
  srsran_vec_fprint_byte(stdout, rrc_msg, rrc_msg_len);  

/*
  const char *rrc_msg_hex_stream = "48d18023a300063046cca38050300221020898478702a49501806000";
  size_t byte_array_length = strlen(rrc_msg_hex_stream) / 2;
  hex_string_to_byte_array(rrc_msg_hex_stream, rrc_msg);
  rrc_msg_len = sizeof(rrc_msg);
  srsran_vec_fprint_byte(stdout, rrc_msg, rrc_msg_len);  */

  cbit_ref bref(&rrc_msg[0], rrc_msg_len);
  bcch_dl_sch_msg_s bcch_msg;
  bcch_msg.unpack(bref);
  sib_type1_s& data = bcch_msg.msg.c1().sib_type1();
  data.cell_access_related_info.tac.from_number(tac);
  data.sched_info_list.clear();
  /*sched_info_s sched_info_elem;
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
  *msg_len = len;
  return 0;
}
int gen_sib1_original(uint8_t* buffer, uint32_t buffer_len, uint32_t* msg_len) {
  const char *rrc_msg_hex_stream = "48d18023a300063046cca38050300221020898478702a49501806000";
  size_t byte_array_length = strlen(rrc_msg_hex_stream) / 2;
  uint8_t rrc_msg[byte_array_length];
  hex_string_to_byte_array(rrc_msg_hex_stream, rrc_msg);
  uint32_t rrc_msg_len = sizeof(rrc_msg);
  cbit_ref bref(&rrc_msg[0], sizeof(rrc_msg));
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

int gen_sib2_acbarring(uint8_t* buffer, uint32_t buffer_len, uint32_t* msg_len) {
  uint8_t* rrc_msg = NULL;
  size_t rrc_msg_len = 0;
  if (read_hex_file_to_byte_array("../output/sib2.hex", &rrc_msg, &rrc_msg_len) != 0) {
      return -1;
  }
  if (rrc_msg_len == 0 || rrc_msg_len > buffer_len) {
      fprintf(stderr, "❌ Invalid message length: %zu\n", rrc_msg_len);
      free(rrc_msg);
      return -1;
  }
  srsran_vec_fprint_byte(stdout, rrc_msg, rrc_msg_len);  

  cbit_ref bref(&rrc_msg[0], sizeof(rrc_msg));
  bcch_dl_sch_msg_s bcch_msg;
  bcch_msg.unpack(bref);
/*
  // 访问并打印 SIB2 消息中的字段
  sib_type2_s& original_data = (&bcch_msg.msg.c1().sys_info().crit_exts)->sys_info_r8().sib_type_and_info[0].sib2();
  int ret_ori = print_sib2_fields(original_data);
  if (ret_ori){
    printf("!!!success print!!!\n");
  } else {
    printf("!!!failed print!!!\n");
  }
*/
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