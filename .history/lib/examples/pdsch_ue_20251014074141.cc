/**
 * Copyright 2013-2023 Software Radio Systems Limited
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
#include <cassert>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <csignal>
#include <pthread.h>
#include <semaphore.h>
#include <sys/time.h>
#include <unistd.h>
#include <strings.h>     // 注意：C++ 没有 <cstrings>，必须保留 .h
#include <complex>
#include <iostream>
#include <vector>
#include <cstdint>
#include <fstream>
#include <string>
#include <iomanip>
#include <filesystem>
#include <sys/stat.h>  // for mkdir
#include "srsran/asn1/rrc.h"
#include "srsran/common/test_common.h"
// C++ 中使用 std::complex 等
using std::complex;
using std::abs;
using std::sqrt;
using std::floor;
#include "srsran/asn1/asn1_utils.h"

// SRSRAN C 头文件：必须用 extern "C" 包裹，防止链接错误
extern "C" {
#include "srsran/common/crash_handler.h"
#include "srsran/common/gen_mch_tables.h"
#include "srsran/phy/io/filesink.h"
#include "srsran/srsran.h"

#ifndef DISABLE_RF
#include "srsran/phy/rf/rf.h"
#include "srsran/phy/rf/rf_utils.h"

cell_search_cfg_t cell_detect_config = {.max_frames_pbch      = SRSRAN_DEFAULT_MAX_FRAMES_PBCH,
  .max_frames_pss       = SRSRAN_DEFAULT_MAX_FRAMES_PSS,
  .nof_valid_pss_frames = SRSRAN_DEFAULT_NOF_VALID_PSS_FRAMES,
  .init_agc             = 0,
  .force_tdd            = false};

#else
#pragma message "Compiling pdsch_ue with no RF support"
#endif
}

#define ENABLE_AGC_DEFAULT
#define MAX_SRATE_DELTA 2



//#define STDOUT_COMPACT


const char* output_file_name;
//#define PRINT_CHANGE_SCHEDULING

//#define CORRECT_SAMPLE_OFFSET

/**********************************************************************
 *  Program arguments processing
 ***********************************************************************/
typedef struct {
  int      nof_subframes;
  int      cpu_affinity;
  bool     disable_plots;
  bool     disable_plots_except_constellation;
  bool     disable_cfo;
  uint32_t time_offset;
  int      force_N_id_2;
  uint16_t rnti;
  const char*    input_file_name;
  int      file_offset_time;
  float    file_offset_freq;
  uint32_t file_nof_prb;
  uint32_t file_nof_ports;
  uint32_t file_cell_id;
  bool     enable_cfo_ref;
  const char*    estimator_alg;
  const char*    rf_dev;
  const char*    rf_args;
  uint32_t rf_nof_rx_ant;
  double   rf_freq;
  float    rf_gain;
  int      net_port;
  const char*    net_address;
  int      net_port_signal;
  const char*    net_address_signal;
  int      decimate;
  int32_t  mbsfn_area_id;
  uint8_t  non_mbsfn_region;
  uint8_t  mbsfn_sf_mask;
  int      tdd_special_sf;
  int      sf_config;
  int      verbose;
  bool     enable_256qam;
  bool     use_standard_lte_rate;
} prog_args_t;

void args_default(prog_args_t* args)
{
  args->disable_plots                      = false;
  args->disable_plots_except_constellation = false;
  args->nof_subframes                      = -1;
  args->rnti                               = SRSRAN_SIRNTI;
  args->force_N_id_2                       = -1; // Pick the best
  args->tdd_special_sf                     = -1;
  args->sf_config                          = -1;
  args->input_file_name                    = NULL;
  args->disable_cfo                        = false;
  args->time_offset                        = 0;
  args->file_nof_prb                       = 25;
  args->file_nof_ports                     = 1;
  args->file_cell_id                       = 0;
  args->file_offset_time                   = 0;
  args->file_offset_freq                   = 0;
  args->rf_dev                             = "";
  args->rf_args                            = "";
  args->rf_freq                            = -1.0;
  args->rf_nof_rx_ant                      = 1;
  args->enable_cfo_ref                     = false;
  args->estimator_alg                      = "interpolate";
  args->enable_256qam                      = false;
#ifdef ENABLE_AGC_DEFAULT
  args->rf_gain = -1.0;
#else
  args->rf_gain = 50.0;
#endif
  args->net_port           = -1;
  args->net_address        = "127.0.0.1";
  args->net_port_signal    = -1;
  args->net_address_signal = "127.0.0.1";
  args->decimate           = 0;
  args->cpu_affinity       = -1;
  args->mbsfn_area_id      = -1;
  args->non_mbsfn_region   = 2;
  args->mbsfn_sf_mask      = 32;
}

void usage(prog_args_t* args, char* prog)
{
  printf("Usage: %s [adgpPoOcildFRDnruMNvTG] -f rx_frequency (in Hz) | -i input_file\n", prog);
#ifndef DISABLE_RF
  printf("\t-I RF dev [Default %s]\n", args->rf_dev);
  printf("\t-a RF args [Default %s]\n", args->rf_args);
  printf("\t-A Number of RX antennas [Default %d]\n", args->rf_nof_rx_ant);
#ifdef ENABLE_AGC_DEFAULT
  printf("\t-g RF fix RX gain [Default AGC]\n");
#else
  printf("\t-g Set RX gain [Default %.1f dB]\n", args->rf_gain);
#endif
#else
  printf("\t   RF is disabled.\n");
#endif
  printf("\t-i input_file [Default use RF board]\n");
  printf("\t-o offset frequency correction (in Hz) for input file [Default %.1f Hz]\n", args->file_offset_freq);
  printf("\t-O offset samples for input file [Default %d]\n", args->file_offset_time);
  printf("\t-p nof_prb for input file [Default %d]\n", args->file_nof_prb);
  printf("\t-P nof_ports for input file [Default %d]\n", args->file_nof_ports);
  printf("\t-c cell_id for input file [Default %d]\n", args->file_cell_id);
  printf("\t-r RNTI in Hex [Default 0x%x]\n", args->rnti);
  printf("\t-l Force N_id_2 [Default best]\n");
  printf("\t-C Disable CFO correction [Default %s]\n", args->disable_cfo ? "Disabled" : "Enabled");
  printf("\t-F Enable RS-based CFO correction [Default %s]\n", !args->enable_cfo_ref ? "Disabled" : "Enabled");
  printf("\t-R Channel estimates algorithm (average, interpolate, wiener) [Default %s]\n", args->estimator_alg);
  printf("\t-t Add time offset [Default %d]\n", args->time_offset);
  printf("\t-T Set TDD special subframe configuration [Default %d]\n", args->tdd_special_sf);
  printf("\t-G Set TDD uplink/downlink configuration [Default %d]\n", args->sf_config);

  printf("\t-y set the cpu affinity mask [Default %d] \n  ", args->cpu_affinity);
  printf("\t-n nof_subframes [Default %d]\n", args->nof_subframes);
  printf("\t-s remote UDP port to send input signal (-1 does nothing with it) [Default %d]\n", args->net_port_signal);
  printf("\t-S remote UDP address to send input signal [Default %s]\n", args->net_address_signal);
  printf("\t-u remote TCP port to send data (-1 does nothing with it) [Default %d]\n", args->net_port);
  printf("\t-U remote TCP address to send data [Default %s]\n", args->net_address);
  printf("\t-M MBSFN area id [Default %d]\n", args->mbsfn_area_id);
  printf("\t-N Non-MBSFN region [Default %d]\n", args->non_mbsfn_region);
  printf("\t-q Enable/Disable 256QAM modulation (default %s)\n", args->enable_256qam ? "enabled" : "disabled");
  printf("\t-Q Use standard LTE sample rates (default %s)\n", args->use_standard_lte_rate ? "enabled" : "disabled");
  printf("\t-v [set srsran_verbose to debug, default none]\n");
}

void parse_args(prog_args_t* args, int argc, char** argv)
{
  int opt;
  args_default(args);

  while ((opt = getopt(argc, argv, "adAogliIpPcOCtdDFRqnvrfuUsSZyWMNBTGQ")) != -1) {
    switch (opt) {
      case 'i':
        args->input_file_name = argv[optind];
        break;
      case 'p':
        args->file_nof_prb = (uint32_t)strtol(argv[optind], NULL, 10);
        break;
      case 'P':
        args->file_nof_ports = (uint32_t)strtol(argv[optind], NULL, 10);
        break;
      case 'o':
        args->file_offset_freq = strtof(argv[optind], NULL);
        break;
      case 'O':
        args->file_offset_time = (int)strtol(argv[optind], NULL, 10);
        break;
      case 'c':
        args->file_cell_id = (uint32_t)strtol(argv[optind], NULL, 10);
        break;
      case 'I':
        args->rf_dev = argv[optind];
        break;
      case 'a':
        args->rf_args = argv[optind];
        break;
      case 'A':
        args->rf_nof_rx_ant = (uint32_t)strtol(argv[optind], NULL, 10);
        break;
      case 'g':
        args->rf_gain = strtof(argv[optind], NULL);
        break;
      case 'C':
        args->disable_cfo = true;
        break;
      case 'F':
        args->enable_cfo_ref = true;
        break;
      case 'R':
        args->estimator_alg = argv[optind];
        break;
      case 't':
        args->time_offset = (uint32_t)strtol(argv[optind], NULL, 10);
        break;
      case 'f':
        args->rf_freq = strtod(argv[optind], NULL);
        break;
      case 'T':
        args->tdd_special_sf = (int)strtol(argv[optind], NULL, 10);
        break;
      case 'G':
        args->sf_config = (int)strtol(argv[optind], NULL, 10);
        break;
      case 'n':
        args->nof_subframes = (int)strtol(argv[optind], NULL, 10);
        break;
      case 'r':
        args->rnti = strtol(argv[optind], NULL, 16);
        break;
      case 'l':
        args->force_N_id_2 = (int)strtol(argv[optind], NULL, 10);
        break;
      case 'u':
        args->net_port = (int)strtol(argv[optind], NULL, 10);
        break;
      case 'U':
        args->net_address = argv[optind];
        break;
      case 's':
        args->net_port_signal = (int)strtol(argv[optind], NULL, 10);
        break;
      case 'S':
        args->net_address_signal = argv[optind];
        break;
      case 'd':
        args->disable_plots = true;
        break;
      case 'D':
        args->disable_plots_except_constellation = true;
        break;
      case 'v':
        increase_srsran_verbose_level();
        args->verbose = get_srsran_verbose_level();
        break;
      case 'Z':
        args->decimate = (int)strtol(argv[optind], NULL, 10);
        break;
      case 'y':
        args->cpu_affinity = (int)strtol(argv[optind], NULL, 10);
        break;
      case 'W':
        output_file_name = argv[optind];
        break;
      case 'M':
        args->mbsfn_area_id = (int32_t)strtol(argv[optind], NULL, 10);
        break;
      case 'N':
        args->non_mbsfn_region = (uint8_t)strtol(argv[optind], NULL, 10);
        break;
      case 'B':
        args->mbsfn_sf_mask = (uint8_t)strtol(argv[optind], NULL, 10);
        break;
      case 'q':
        args->enable_256qam ^= true;
        break;
      case 'Q':
        args->use_standard_lte_rate ^= true;
        break;
      default:
        usage(args, argv[0]);
        exit(-1);
    }
  }
  if (args->rf_freq < 0 && args->input_file_name == NULL) {
    usage(args, argv[0]);
    exit(-1);
  }
}

/**********************************************************************/

uint8_t* data[SRSRAN_MAX_CODEWORDS];

bool go_exit = false;

void sig_int_handler(int signo)
{
  printf("SIGINT received. Exiting...\n");
  if (signo == SIGINT) {
    go_exit = true;
  } else if (signo == SIGSEGV) {
    exit(1);
  }
}

cf_t* sf_buffer[SRSRAN_MAX_PORTS] = {NULL};

#ifndef DISABLE_RF

int srsran_rf_recv_wrapper(void* h, cf_t* data_[SRSRAN_MAX_PORTS], uint32_t nsamples, srsran_timestamp_t* t)
{
  DEBUG(" ----  Receive %d samples  ----", nsamples);
  void* ptr[SRSRAN_MAX_PORTS];
  for (int i = 0; i < SRSRAN_MAX_PORTS; i++) {
    ptr[i] = data_[i];
  }
  return srsran_rf_recv_with_time_multi((srsran_rf_t*)h, ptr, nsamples, true, NULL, NULL);
}

static SRSRAN_AGC_CALLBACK(srsran_rf_set_rx_gain_th_wrapper_)
{
  srsran_rf_set_rx_gain_th((srsran_rf_t*)h, gain_db);
}

#endif

extern float mean_exec_time;

enum receiver_state { DECODE_MIB, DECODE_PDSCH } state;

srsran_cell_t      cell;
srsran_ue_dl_t     ue_dl;
srsran_ue_dl_cfg_t ue_dl_cfg;
srsran_dl_sf_cfg_t dl_sf;
srsran_pdsch_cfg_t pdsch_cfg;
srsran_ue_sync_t   ue_sync;
prog_args_t        prog_args;

uint32_t pkt_errors = 0, pkt_total = 0, nof_detected = 0, pmch_pkt_errors = 0, pmch_pkt_total = 0, nof_trials = 0;

srsran_netsink_t net_sink, net_sink_signal;
/* Useful macros for printing lines which will disappear */

#define PRINT_LINE_INIT()                                                                                              \
  int        this_nof_lines = 0;                                                                                       \
  static int prev_nof_lines = 0
#define PRINT_LINE(_fmt, ...)                                                                                          \
  printf("\033[K" _fmt "\n", ##__VA_ARGS__);                                                                           \
  this_nof_lines++
#define PRINT_LINE_RESET_CURSOR()                                                                                      \
  printf("\033[%dA", this_nof_lines);                                                                                  \
  prev_nof_lines = this_nof_lines
#define PRINT_LINE_ADVANCE_CURSOR() printf("\033[%dB", prev_nof_lines + 1)

void handle_pdsch_pdu(srsran_pdsch_cfg_t* pdsch_cfg, uint8_t* data[SRSRAN_MAX_CODEWORDS]);
void save_mib_and_cell_info(
  const uint8_t*       bch_payload,    // 24 字节原始 MIB payload
  const srsran_cell_t& cell);          // 小区配置（不含 SFN）
bool save_to_output(const std::string& filename, const std::string& content);
void pack_bits_to_bytes(const uint8_t* bits, uint8_t* bytes);
int main(int argc, char** argv)
{
  int ret;

#ifndef DISABLE_RF
  srsran_rf_t rf;
#endif

  srsran_debug_handle_crash(argc, argv);

  parse_args(&prog_args, argc, argv);

  srsran_use_standard_symbol_size(prog_args.use_standard_lte_rate);


  for (int i = 0; i < SRSRAN_MAX_CODEWORDS; i++) {
    data[i] = srsran_vec_u8_malloc(2000 * 8);
    if (!data[i]) {
      ERROR("Allocating data");
      go_exit = true;
    }
  }

  uint8_t mch_table[10];
  bzero(&mch_table[0], sizeof(uint8_t) * 10);
  if (prog_args.mbsfn_area_id > -1) {
    generate_mcch_table(mch_table, prog_args.mbsfn_sf_mask);
  }
  if (prog_args.cpu_affinity > -1) {
    cpu_set_t cpuset;
    pthread_t thread;

    thread = pthread_self();
    for (int i = 0; i < 8; i++) {
      if (((prog_args.cpu_affinity >> i) & 0x01) == 1) {
        printf("Setting pdsch_ue with affinity to core %d\n", i);
        CPU_SET((size_t)i, &cpuset);
      }
      if (pthread_setaffinity_np(thread, sizeof(cpu_set_t), &cpuset)) {
        ERROR("Error setting main thread affinity to %d", prog_args.cpu_affinity);
        exit(-1);
      }
    }
  }

  if (prog_args.net_port > 0) {
    if (srsran_netsink_init(&net_sink, prog_args.net_address, prog_args.net_port, SRSRAN_NETSINK_UDP)) {
      ERROR("Error initiating UDP socket to %s:%d", prog_args.net_address, prog_args.net_port);
      exit(-1);
    }
    srsran_netsink_set_nonblocking(&net_sink);
  }
  if (prog_args.net_port_signal > 0) {
    if (srsran_netsink_init(
            &net_sink_signal, prog_args.net_address_signal, prog_args.net_port_signal, SRSRAN_NETSINK_UDP)) {
      ERROR("Error initiating UDP socket to %s:%d", prog_args.net_address_signal, prog_args.net_port_signal);
      exit(-1);
    }
    srsran_netsink_set_nonblocking(&net_sink_signal);
  }

  float search_cell_cfo = 0;

#ifndef DISABLE_RF
  if (!prog_args.input_file_name) {
    printf("Opening RF device with %d RX antennas...\n", prog_args.rf_nof_rx_ant);
    if (srsran_rf_open_devname(&rf, 
      prog_args.rf_dev, 
      const_cast<char*>(prog_args.rf_args), 
      prog_args.rf_nof_rx_ant)) {
      fprintf(stderr, "Error opening rf\n");
      exit(-1);
    }
    /* Set receiver gain */
    if (prog_args.rf_gain > 0) {
      srsran_rf_set_rx_gain(&rf, prog_args.rf_gain);
    } else {
      printf("Starting AGC thread...\n");
      if (srsran_rf_start_gain_thread(&rf, false)) {
        ERROR("Error opening rf");
        exit(-1);
      }
      srsran_rf_set_rx_gain(&rf, srsran_rf_get_rx_gain(&rf));
      cell_detect_config.init_agc = srsran_rf_get_rx_gain(&rf);
    }

    sigset_t sigset;
    sigemptyset(&sigset);
    sigaddset(&sigset, SIGINT);
    sigprocmask(SIG_UNBLOCK, &sigset, NULL);
    signal(SIGINT, sig_int_handler);

    /* set receiver frequency */
    printf("Tuning receiver to %.3f MHz\n", (prog_args.rf_freq + prog_args.file_offset_freq) / 1000000);
    srsran_rf_set_rx_freq(&rf, prog_args.rf_nof_rx_ant, prog_args.rf_freq + prog_args.file_offset_freq);

    uint32_t ntrial = 0;
    do {
      ret = rf_search_and_decode_mib(
          &rf, prog_args.rf_nof_rx_ant, &cell_detect_config, prog_args.force_N_id_2, &cell, &search_cell_cfo);
      if (ret < 0) {
        ERROR("Error searching for cell");
        exit(-1);
      } else if (ret == 0 && !go_exit) {
        printf("Cell not found after [%4d] attempts. Trying again... (Ctrl+C to exit)\n", ntrial++);
      }
    } while (ret == 0 && !go_exit);

    if (go_exit) {
      srsran_rf_close(&rf);
      exit(0);
    }

    /* set sampling frequency */
    int srate = srsran_sampling_freq_hz(cell.nof_prb);
    if (srate != -1) {
      printf("Setting rx sampling rate %.2f MHz\n", (float)srate / 1000000);
      float srate_rf = srsran_rf_set_rx_srate(&rf, (double)srate);
      if (abs(srate - (int)srate_rf) > MAX_SRATE_DELTA) {
        ERROR("Could not set rx sampling rate : wanted %d got %f", srate, srate_rf);
        exit(-1);
      }
    } else {
      ERROR("Invalid number of PRB %d", cell.nof_prb);
      exit(-1);
    }

    INFO("Stopping RF and flushing buffer...\r");
  }
#endif

  /* If reading from file, go straight to PDSCH decoding. Otherwise, decode MIB first */
  if (prog_args.input_file_name) {
    /* preset cell configuration */
    cell.id              = prog_args.file_cell_id;
    cell.cp              = SRSRAN_CP_NORM;
    cell.phich_length    = SRSRAN_PHICH_NORM;
    cell.phich_resources = SRSRAN_PHICH_R_1;
    cell.nof_ports       = prog_args.file_nof_ports;
    cell.nof_prb         = prog_args.file_nof_prb;

    if (srsran_ue_sync_init_file_multi(&ue_sync,
                                       prog_args.file_nof_prb,
                                       const_cast<char*>(prog_args.input_file_name),                                       prog_args.file_offset_time,
                                       prog_args.file_offset_freq,
                                       prog_args.rf_nof_rx_ant)) {
      ERROR("Error initiating ue_sync");
      exit(-1);
    }

  } else {
#ifndef DISABLE_RF
    int decimate = 0;
    if (prog_args.decimate) {
      if (prog_args.decimate > 4 || prog_args.decimate < 0) {
        printf("Invalid decimation factor, setting to 1 \n");
      } else {
        decimate = prog_args.decimate;
      }
    }
    if (srsran_ue_sync_init_multi_decim(&ue_sync,
                                        cell.nof_prb,
                                        cell.id == 1000,
                                        srsran_rf_recv_wrapper,
                                        prog_args.rf_nof_rx_ant,
                                        (void*)&rf,
                                        decimate)) {
      ERROR("Error initiating ue_sync");
      exit(-1);
    }
    if (srsran_ue_sync_set_cell(&ue_sync, cell)) {
      ERROR("Error initiating ue_sync");
      exit(-1);
    }
#endif
  }

  uint32_t max_num_samples = 3 * SRSRAN_SF_LEN_PRB(cell.nof_prb); /// Length in complex samples
  for (uint32_t i = 0; i < prog_args.rf_nof_rx_ant; i++){
    sf_buffer[i] = srsran_vec_cf_malloc(max_num_samples);
  }
  srsran_ue_mib_t ue_mib;
  if (srsran_ue_mib_init(&ue_mib, sf_buffer[0], cell.nof_prb)) {
    ERROR("Error initaiting UE MIB decoder");
    exit(-1);
  }
  if (srsran_ue_mib_set_cell(&ue_mib, cell)) {
    ERROR("Error initaiting UE MIB decoder");
    exit(-1);
  }

  if (srsran_ue_dl_init(&ue_dl, sf_buffer, cell.nof_prb, prog_args.rf_nof_rx_ant)) {
    ERROR("Error initiating UE downlink processing module");
    exit(-1);
  }
  if (srsran_ue_dl_set_cell(&ue_dl, cell)) {
    ERROR("Error initiating UE downlink processing module");
    exit(-1);
  }

  // Disable CP based CFO estimation during find
  ue_sync.cfo_current_value       = search_cell_cfo / 15000;
  ue_sync.cfo_is_copied           = true;
  ue_sync.cfo_correct_enable_find = true;
  srsran_sync_set_cfo_cp_enable(&ue_sync.sfind, false, 0);

  ZERO_OBJECT(ue_dl_cfg);
  ZERO_OBJECT(dl_sf);
  ZERO_OBJECT(pdsch_cfg);

  pdsch_cfg.meas_evm_en = true;

  if (cell.frame_type == SRSRAN_TDD && prog_args.tdd_special_sf >= 0 && prog_args.sf_config >= 0) {
    dl_sf.tdd_config.ss_config  = prog_args.tdd_special_sf;
    dl_sf.tdd_config.sf_config  = prog_args.sf_config;
    dl_sf.tdd_config.configured = true;
  }

  srsran_chest_dl_cfg_t chest_pdsch_cfg = {};
  chest_pdsch_cfg.cfo_estimate_enable   = prog_args.enable_cfo_ref;
  chest_pdsch_cfg.cfo_estimate_sf_mask  = 1023;
  chest_pdsch_cfg.estimator_alg         = srsran_chest_dl_str2estimator_alg(prog_args.estimator_alg);
  chest_pdsch_cfg.sync_error_enable     = true;

  // Special configuration for MBSFN channel estimation
  srsran_chest_dl_cfg_t chest_mbsfn_cfg = {};
  chest_mbsfn_cfg.filter_type           = SRSRAN_CHEST_FILTER_TRIANGLE;
  chest_mbsfn_cfg.filter_coef[0]        = 0.1;
  chest_mbsfn_cfg.estimator_alg         = SRSRAN_ESTIMATOR_ALG_INTERPOLATE;
  chest_mbsfn_cfg.noise_alg             = SRSRAN_NOISE_ALG_PSS;

  // Allocate softbuffer buffers
  srsran_softbuffer_rx_t rx_softbuffers[SRSRAN_MAX_CODEWORDS];
  for (uint32_t i = 0; i < SRSRAN_MAX_CODEWORDS; i++) {
    pdsch_cfg.softbuffers.rx[i] = &rx_softbuffers[i];
    srsran_softbuffer_rx_init(pdsch_cfg.softbuffers.rx[i], cell.nof_prb);
  }

  pdsch_cfg.rnti = prog_args.rnti;

  /* Configure MBSFN area id and non-MBSFN Region */
  if (prog_args.mbsfn_area_id > -1) {
    srsran_ue_dl_set_mbsfn_area_id(&ue_dl, prog_args.mbsfn_area_id);
    srsran_ue_dl_set_non_mbsfn_region(&ue_dl, prog_args.non_mbsfn_region);
  }



#ifndef DISABLE_RF
  if (!prog_args.input_file_name) {
    srsran_rf_start_rx_stream(&rf, false);
  }
#endif

#ifndef DISABLE_RF
  if (prog_args.rf_gain < 0 && !prog_args.input_file_name) {
    srsran_rf_info_t* rf_info = srsran_rf_get_info(&rf);
    srsran_ue_sync_start_agc(&ue_sync,
                             srsran_rf_set_rx_gain_th_wrapper_,
                             rf_info->min_rx_gain,
                             rf_info->max_rx_gain,
                             cell_detect_config.init_agc);
  }
#endif
#ifdef PRINT_CHANGE_SCHEDULING
  srsran_ra_dl_grant_t old_dl_dci;
  bzero(&old_dl_dci, sizeof(srsran_ra_dl_grant_t));
#endif

  ue_sync.cfo_correct_enable_track = !prog_args.disable_cfo;

  srsran_pbch_decode_reset(&ue_mib.pbch);

  INFO("\nEntering main loop...");

  // Variables for measurements
  uint32_t nframes = 0;
  float    rsrp0 = 0.0, rsrp1 = 0.0, rsrq = 0.0, snr = 0.0, enodebrate = 0.0, uerate = 0.0, procrate = 0.0,
        sinr[SRSRAN_MAX_LAYERS][SRSRAN_MAX_CODEBOOKS] = {}, sync_err[SRSRAN_MAX_PORTS][SRSRAN_MAX_PORTS] = {};
  bool decode_pdsch = false;

  for (int i = 0; i < SRSRAN_MAX_LAYERS; i++) {
    srsran_vec_f_zero(sinr[i], SRSRAN_MAX_CODEBOOKS);
  }

  /* Main loop */
  uint64_t sf_cnt          = 0;
  uint32_t sfn             = 0;
  uint32_t last_decoded_tm = 0;
  while (!go_exit && 
    (sf_cnt < (uint64_t)prog_args.nof_subframes || 
     (int32_t)prog_args.nof_subframes == -1)) {
    char input[128];
    PRINT_LINE_INIT();

    fd_set set;
    FD_ZERO(&set);
    FD_SET(0, &set);

    struct timeval to;
    to.tv_sec  = 0;
    to.tv_usec = 0;

    /* Set default verbose level */
    set_srsran_verbose_level(prog_args.verbose);
    int n = select(1, &set, NULL, NULL, &to);
    if (n == 1) {
      /* If a new line is detected set verbose level to Debug */
      if (fgets(input, sizeof(input), stdin)) {
        set_srsran_verbose_level(SRSRAN_VERBOSE_DEBUG);
        pkt_errors   = 0;
        pkt_total    = 0;
        nof_detected = 0;
        nof_trials   = 0;
      }
    }

    cf_t* buffers[SRSRAN_MAX_CHANNELS] = {};
    for (int p = 0; p < SRSRAN_MAX_PORTS; p++) {
      buffers[p] = sf_buffer[p];
    }
    ret = srsran_ue_sync_zerocopy(&ue_sync, buffers, max_num_samples);
    if (ret < 0) {
      ERROR("Error calling srsran_ue_sync_work()");
    }

#ifdef CORRECT_SAMPLE_OFFSET
    float sample_offset =
        (float)srsran_ue_sync_get_last_sample_offset(&ue_sync) + srsran_ue_sync_get_sfo(&ue_sync) / 1000;
    srsran_ue_dl_set_sample_offset(&ue_dl, sample_offset);
#endif

    /* srsran_ue_sync_get_buffer returns 1 if successfully read 1 aligned subframe */
    if (ret == 1) {
      bool           acks[SRSRAN_MAX_CODEWORDS] = {false};
      struct timeval t[3];

      uint32_t sf_idx = srsran_ue_sync_get_sfidx(&ue_sync);

      switch (state) {
        case DECODE_MIB:
          if (sf_idx == 0) {
            uint8_t bch_payload[SRSRAN_BCH_PAYLOAD_LEN];
            int     sfn_offset;
            n = srsran_ue_mib_decode(&ue_mib, bch_payload, NULL, &sfn_offset);
            if (n < 0) {
              ERROR("Error decoding UE MIB");
              exit(-1);
            } else if (n == SRSRAN_UE_MIB_FOUND) {
              srsran_pbch_mib_unpack(bch_payload, &cell, &sfn);
              srsran_cell_fprint(stdout, &cell, sfn);
              printf("Decoded MIB. SFN: %d, offset: %d\n", sfn, sfn_offset);
              save_mib_and_cell_info(bch_payload, cell);
              

              sfn   = (sfn + sfn_offset) % 1024;
              state = DECODE_PDSCH;
            }
          }
          break;
        case DECODE_PDSCH:

          if (prog_args.rnti != SRSRAN_SIRNTI) {
            decode_pdsch = true;
            if (srsran_sfidx_tdd_type(dl_sf.tdd_config, sf_idx) == SRSRAN_TDD_SF_U) {
              decode_pdsch = false;
            }
          } else {
            /* We are looking for SIB1 Blocks, search only in appropiate places */
            if ((sf_idx == 5 && (sfn % 2) == 0) || (sf_idx == 0 && (sfn % 16) == 0) || mch_table[sf_idx] == 1) {
            //if (mch_table[sf_idx] == 1) {

              decode_pdsch = true;
            } else {
              decode_pdsch = false;
            }
          }

          uint32_t tti = sfn * 10 + sf_idx;

          gettimeofday(&t[1], NULL);
          if (decode_pdsch) {
            srsran_sf_t sf_type;
            if (mch_table[sf_idx] == 0 || prog_args.mbsfn_area_id < 0) { // Not an MBSFN subframe
              sf_type = SRSRAN_SF_NORM;

              // Set PDSCH channel estimation
              ue_dl_cfg.chest_cfg = chest_pdsch_cfg;
            } else {
              sf_type = SRSRAN_SF_MBSFN;

              // Set MBSFN channel estimation
              ue_dl_cfg.chest_cfg = chest_mbsfn_cfg;
            }

            n = 0;
            for (uint32_t tm = 0; tm < 4 && !n; tm++) {
              dl_sf.tti                             = tti;
              dl_sf.sf_type                         = sf_type;
              ue_dl_cfg.cfg.tm                      = (srsran_tm_t)tm;
              ue_dl_cfg.cfg.pdsch.use_tbs_index_alt = prog_args.enable_256qam;

              if ((ue_dl_cfg.cfg.tm == SRSRAN_TM1 && cell.nof_ports == 1) ||
                  (ue_dl_cfg.cfg.tm > SRSRAN_TM1 && cell.nof_ports > 1)) {
                n = srsran_ue_dl_find_and_decode(&ue_dl, &dl_sf, &ue_dl_cfg, &pdsch_cfg, data, acks);
                if (n > 0) {
                  nof_detected++;
                  last_decoded_tm = tm;
                  for (uint32_t tb = 0; tb < SRSRAN_MAX_CODEWORDS; tb++) {
                    handle_pdsch_pdu(&pdsch_cfg, data);
                    if (pdsch_cfg.grant.tb[tb].enabled) {
                      if (!acks[tb]) {
                        if (sf_type == SRSRAN_SF_NORM) {
                          pkt_errors++;
                        } else {
                          pmch_pkt_errors++;
                        }
                      }
                      if (sf_type == SRSRAN_SF_NORM) {
                        pkt_total++;
                      } else {
                        pmch_pkt_total++;
                      }
                    }
                  }
                }
              }
            }
            // Feed-back ue_sync with chest_dl CFO estimation
            if (sf_idx == 5 && prog_args.enable_cfo_ref) {
              srsran_ue_sync_set_cfo_ref(&ue_sync, ue_dl.chest_res.cfo);
            }

            gettimeofday(&t[2], NULL);
            get_time_interval(t);

            if (n > 0) {
              /* Send data if socket active */
              if (prog_args.net_port > 0) {
                if (sf_idx == 1) {
                  srsran_netsink_write(&net_sink, data[0], 1 + (n - 1) / 8);
                } else {
                  // TODO: UDP Data transmission does not work
                  for (uint32_t tb = 0; tb < SRSRAN_MAX_CODEWORDS; tb++) {
                    if (pdsch_cfg.grant.tb[tb].enabled) {
                      srsran_netsink_write(&net_sink, data[tb], 1 + (pdsch_cfg.grant.tb[tb].tbs - 1) / 8);
                    }
                  }
                }
              }
#ifdef PRINT_CHANGE_SCHEDULING
              if (pdsch_cfg.dci.cw[0].mcs_idx != old_dl_dci.cw[0].mcs_idx ||
                  memcmp(&pdsch_cfg.dci.type0_alloc, &old_dl_dci.type0_alloc, sizeof(srsran_ra_type0_t)) ||
                  memcmp(&pdsch_cfg.dci.type1_alloc, &old_dl_dci.type1_alloc, sizeof(srsran_ra_type1_t)) ||
                  memcmp(&pdsch_cfg.dci.type2_alloc, &old_dl_dci.type2_alloc, sizeof(srsran_ra_type2_t))) {
                old_dl_dci = pdsch_cfg.dci;
                fflush(stdout);
                printf("DCI %s\n", srsran_dci_format_string(pdsch_cfg.dci.dci_format));
                srsran_ra_pdsch_fprint(stdout, &old_dl_dci, cell.nof_prb);
              }
#endif
            }

            nof_trials++;

            uint32_t enb_bits = ((pdsch_cfg.grant.tb[0].enabled ? pdsch_cfg.grant.tb[0].tbs : 0) +
                                 (pdsch_cfg.grant.tb[1].enabled ? pdsch_cfg.grant.tb[1].tbs : 0));
            uint32_t ue_bits  = ((acks[0] ? pdsch_cfg.grant.tb[0].tbs : 0) + (acks[1] ? pdsch_cfg.grant.tb[1].tbs : 0));
            rsrq              = SRSRAN_VEC_EMA(ue_dl.chest_res.rsrp_dbm, rsrq, 0.1f);
            rsrp0             = SRSRAN_VEC_EMA(ue_dl.chest_res.rsrp_port_dbm[0], rsrp0, 0.05f);
            rsrp1             = SRSRAN_VEC_EMA(ue_dl.chest_res.rsrp_port_dbm[1], rsrp1, 0.05f);
            snr               = SRSRAN_VEC_EMA(ue_dl.chest_res.snr_db, snr, 0.05f);
            enodebrate        = SRSRAN_VEC_EMA(enb_bits / 1000.0f, enodebrate, 0.05f);
            uerate            = SRSRAN_VEC_EMA(ue_bits / 1000.0f, uerate, 0.001f);
            if (chest_pdsch_cfg.sync_error_enable) {
              for (uint32_t i = 0; i < cell.nof_ports; i++) {
                for (uint32_t j = 0; j < prog_args.rf_nof_rx_ant; j++) {
                  sync_err[i][j] = SRSRAN_VEC_EMA(ue_dl.chest.sync_err[i][j], sync_err[i][j], 0.001f);
                  if (!isnormal(sync_err[i][j])) {
                    sync_err[i][j] = 0.0f;
                  }
                }
              }
            }
            float elapsed = (float)t[0].tv_usec + t[0].tv_sec * 1.0e+6f;
            if (elapsed != 0.0f) {
              procrate = SRSRAN_VEC_EMA(ue_bits / elapsed, procrate, 0.01f);
            }

            nframes++;
            if (isnan(rsrq)) {
              rsrq = 0;
            }
            if (isnan(snr)) {
              snr = 0;
            }
            if (isnan(rsrp0)) {
              rsrp0 = 0;
            }
            if (isnan(rsrp1)) {
              rsrp1 = 0;
            }
          }

          // Plot and Printf
          if (sf_idx == 5) {
            float gain = prog_args.rf_gain;
            if (gain < 0) {
              gain = srsran_convert_power_to_dB(srsran_agc_get_gain(&ue_sync.agc));
            }

            /* Print transmission scheme */

            /* Print basic Parameters */
            PRINT_LINE("          CFO: %+7.2f Hz", srsran_ue_sync_get_cfo(&ue_sync));
            PRINT_LINE("         RSRP: %+5.1f dBm | %+5.1f dBm", rsrp0, rsrp1);
            PRINT_LINE("          SNR: %+5.1f dB", snr);
            PRINT_LINE("           TM: %d", last_decoded_tm + 1);
            PRINT_LINE(
                "           Rb: %6.2f / %6.2f / %6.2f Mbps (net/maximum/processing)", uerate, enodebrate, procrate);
            PRINT_LINE("   PDCCH-Miss: %5.2f%%", 100 * (1 - (float)nof_detected / nof_trials));
            PRINT_LINE("   PDSCH-BLER: %5.2f%%", (float)100 * pkt_errors / pkt_total);
            PRINT_LINE("   PDSCH-EVM: %5.2f%%", ue_dl.pdsch.avg_evm);

            if (prog_args.mbsfn_area_id > -1) {
              PRINT_LINE("   PMCH-BLER: %5.2f%%", (float)100 * pkt_errors / pmch_pkt_total);
            }

            PRINT_LINE("         TB 0: mcs=%d; tbs=%d", pdsch_cfg.grant.tb[0].mcs_idx, pdsch_cfg.grant.tb[0].tbs);
            PRINT_LINE("         TB 1: mcs=%d; tbs=%d", pdsch_cfg.grant.tb[1].mcs_idx, pdsch_cfg.grant.tb[1].tbs);

            /* MIMO: if tx and rx antennas are bigger than 1 */
            if (cell.nof_ports > 1 && ue_dl.pdsch.nof_rx_antennas > 1) {
              uint32_t ri = 0;
              float    cn = 0;
              /* Compute condition number */
              if (srsran_ue_dl_select_ri(&ue_dl, &ri, &cn)) {
                /* Condition number calculation is not supported for the number of tx & rx antennas*/
                PRINT_LINE("            κ: NA");
              } else {
                /* Print condition number */
                PRINT_LINE("            κ: %.1f dB, RI=%d (Condition number, 0 dB => Best)", cn, ri);
              }
              PRINT_LINE("");
            }
            if (chest_pdsch_cfg.sync_error_enable) {
              for (uint32_t i = 0; i < cell.nof_ports; i++) {
                for (uint32_t j = 0; j < prog_args.rf_nof_rx_ant; j++) {
                  PRINT_LINE("sync_err[%d][%d]=%f", i, j, sync_err[i][j]);
                }
              }
            }
            PRINT_LINE("Press enter maximum printing debug log of 1 subframe.");
            PRINT_LINE("");
            PRINT_LINE_RESET_CURSOR();
          }
          break;
      }
      if (sf_idx == 9) {
        sfn++;
        if (sfn == 1024) {
          sfn = 0;
          PRINT_LINE_ADVANCE_CURSOR();
          pkt_errors      = 0;
          pkt_total       = 0;
          pmch_pkt_errors = 0;
          pmch_pkt_total  = 0;
        }
      }


    } else if (ret == 0) {
      printf("Finding PSS... Peak: %8.1f, FrameCnt: %d, State: %d\r",
             srsran_sync_get_peak_value(&ue_sync.sfind),
             ue_sync.frame_total_cnt,
             ue_sync.state);

    }

    sf_cnt++;
  } // Main loop

  srsran_ue_dl_free(&ue_dl);
  srsran_ue_sync_free(&ue_sync);
  for (int i = 0; i < SRSRAN_MAX_CODEWORDS; i++) {
    if (data[i]) {
      free(data[i]);
    }
  }
  for (uint32_t i = 0; i < prog_args.rf_nof_rx_ant; i++){
      if (sf_buffer[i]) {
      free(sf_buffer[i]);
    }
  }

#ifndef DISABLE_RF
  if (!prog_args.input_file_name) {
    srsran_ue_mib_free(&ue_mib);
    srsran_rf_close(&rf);
  }
#endif

  printf("\nBye\n");
  exit(0);
}
//把GUI删了
using namespace asn1;
using namespace asn1::rrc;


// 缓存：只在收到时保存一次
static std::string sib1_json;
static std::string sib2_json;
static std::string sib1_hex;
static std::string sib2_hex;

static bool sibs_completed = false;

// 辅助函数：将字节数组转为连续小写 hex 字符串
std::string bytes_to_hex(const uint8_t* data, size_t len) {
  std::stringstream ss;
  ss << std::hex << std::setfill('0');
  for (size_t i = 0; i < len; ++i) {
    ss << std::setw(2) << static_cast<int>(data[i]);
  }
  return ss.str();
}

void handle_pdsch_pdu(srsran_pdsch_cfg_t* pdsch_cfg, uint8_t* data[SRSRAN_MAX_CODEWORDS]) {
  if (sibs_completed) {
    return; // 已完成，不再处理
  }

  int nof_tb = pdsch_cfg->grant.nof_tb;

  if (pdsch_cfg->rnti == SRSRAN_SIRNTI) {
    printf("Received SI message - RNTI: 0xFFFE (SI-RNTI)\n");

    for (int i = 0; i < nof_tb; i++) {
      if (!pdsch_cfg->grant.tb[i].enabled) continue;

      int len = pdsch_cfg->grant.tb[i].tbs / 8;
      if (len <= 0) continue;

      printf("TB %d: TBS = %d bits (%d bytes)\n", i, pdsch_cfg->grant.tb[i].tbs, len);

      cbit_ref bref(data[i], len);
      bcch_dl_sch_msg_s bcch_msg;
      if (bcch_msg.unpack(bref) != SRSASN_SUCCESS) {
        printf("Failed to unpack BCCH DL-SCH message\n");
        continue;
      }

      if (bcch_msg.msg.type() == bcch_dl_sch_msg_type_c::types::c1) {
        auto& c1 = bcch_msg.msg.c1();

        // === 处理 SIB1 ===
        if (c1.type() == bcch_dl_sch_msg_type_c::c1_c_::types::sib_type1) {
          if (sib1_json.empty()) {
            printf("✅ Decoded SIB1 successfully\n");

            // 保存 JSON
            json_writer js;
            c1.sib_type1().to_json(js);
            sib1_json = js.to_string();

            // 保存十六进制原始数据
            sib1_hex = bytes_to_hex(data[i], len);
          }
        }

        // === 处理 SystemInfo (包含 SIB2) ===
        else if (c1.type() == bcch_dl_sch_msg_type_c::c1_c_::types::sys_info) {
          if (sib2_json.empty()) {
            printf("✅ Decoded SystemInfo (possible SIB2)\n");

            auto* crit_exts = &c1.sys_info().crit_exts;
            if (crit_exts->type() == sys_info_s::crit_exts_c_::types::sys_info_r8) {
              sys_info_r8_ies_s& r8 = crit_exts->sys_info_r8();
              for (auto& item : r8.sib_type_and_info) {
                if (item.type() == sib_info_item_c::types::sib2) {
                  printf("✅ Found SIB2 inside SystemInfo\n");

                  // 保存 JSON
                  json_writer js;
                  item.sib2().to_json(js);
                  sib2_json = js.to_string();

                  // 保存十六进制原始数据
                  sib2_hex = bytes_to_hex(data[i], len);

                  break;
                }
              }
            }
          }
        }

        if (!sib1_json.empty() && !sib2_json.empty()) {
          printf("\n🎉 Both SIB1 and SIB2 captured! Writing all files once and exiting...\n");
          save_to_output("sib1.json", sib1_json);
          save_to_output("sib2.json", sib2_json);
          save_to_output("sib1.hex", sib1_hex);
          save_to_output("sib2.hex", sib2_hex);
          sibs_completed = true;
          exit(0); // 成功获取全部，退出
        }
      }
    }
  }
}



void save_mib_and_cell_info(const uint8_t* bch_payload, const srsran_cell_t& cell)
{
  static bool saved = false;
  if (saved) {
    return; // 确保只保存一次
  }
  uint8_t rrc_msg[3];
  pack_bits_to_bytes(bch_payload, rrc_msg);  // 打包 24 bits -> 3 bytes
  //uint8_t  rrc_msg[]   = {0x94, 0x64, 0xC0};
  int rrc_msg_len = sizeof(rrc_msg); // = 3
  cbit_ref bref(&rrc_msg[0], rrc_msg_len);
  bcch_bch_msg_s bcch_bch_msg;
  bcch_bch_msg.unpack(bref);

  mib_s& mib = bcch_bch_msg.msg; // ✅ 使用解码后的 mib

  printf("🎉 Saving MIB and Cell info to files...\n");
  std::string hex_str;
  for (int i = 0; i < rrc_msg_len; ++i) {
    char buf[3];
    snprintf(buf, sizeof(buf), "%02x", rrc_msg[i]);
    hex_str += buf;
  }
  save_to_output("mib.hex", hex_str);

  asn1::json_writer js_mib;
  mib.to_json(js_mib); 
  std::string mib_json_str = js_mib.to_string();
  save_to_output("mib.json", mib_json_str);

  // --- 3. 保存 Cell JSON ---
  asn1::json_writer js_cell;
  js_cell.start_obj();  // ✅ 不是 start_object()
  js_cell.write_str("Type", cell.frame_type == SRSRAN_FDD ? "FDD" : "TDD");
  js_cell.write_int("PCI", cell.id);
  js_cell.write_int("Nof ports", cell.nof_ports);
  js_cell.write_str("CP", srsran_cp_string(cell.cp));
  js_cell.write_int("PRB", cell.nof_prb);

  // PHICH Length
  js_cell.write_str("PHICH Length", 
                   cell.phich_length == SRSRAN_PHICH_NORM ? "normal" : "extended");

  // PHICH Resources
  int phich_res_str;
  switch (cell.phich_resources) {
    case SRSRAN_PHICH_R_1_6: phich_res_str = 0; break;
    case SRSRAN_PHICH_R_1_2: phich_res_str = 1;     break;
    case SRSRAN_PHICH_R_1:   phich_res_str = 2;      break;
    case SRSRAN_PHICH_R_2:   phich_res_str = 3;      break;
    default:                 phich_res_str = 4;    break;
  }
  js_cell.write_int("PHICH Resources", phich_res_str);
  js_cell.end_obj();  // ✅ 不是 end_object()
  save_to_output("cell.json", js_cell.to_string());
  saved = true;
}


/**
 * @brief 将内容写入 output/ 目录下的指定文件，自动创建目录，并在内容末尾添加 \n
 * 
 * @param filename 文件名（如 "mib.hex", "cell.json"）
 * @param content  要写入的内容（无需手动加 \n）
 * @return true     成功
 * @return false    失败
 */
#ifdef _WIN32
  #include <direct.h>  // Windows
  #define MKDIR(path) _mkdir(path)
#else
  #define MKDIR(path) mkdir(path, 0755)
#endif

bool save_to_output(const std::string& filename, const std::string& content) {
  // ✅ 函数内固定路径
  const std::string base_dir = "../output";
  const std::string filepath = base_dir + "/" + filename;

  // 检查目录是否存在（简单判断：尝试创建，如果失败可能是已存在）
  if (MKDIR(base_dir.c_str()) != 0) {
    // 如果 mkdir 失败，检查是否是因为目录已存在
    struct stat info;
    if (stat(base_dir.c_str(), &info) != 0 || !(info.st_mode & S_IFDIR)) {
      std::cerr << "❌ Failed to create directory: " << base_dir << std::endl;
      return false;
    }
  }

  // 写入文件（自动添加 \n）
  std::ofstream file(filepath);
  if (!file.is_open()) {
    std::cerr << "❌ Cannot open file for writing: " << filepath << std::endl;
    return false;
  }

  file << content << '\n';  // ✅ 自动添加换行符
  if (file.fail()) {
    std::cerr << "❌ Error writing to file: " << filepath << std::endl;
    file.close();
    return false;
  }

  file.close();
  printf("📄 Wrote to file: %s\n", filepath.c_str());
  return true;
}
void pack_bits_to_bytes(const uint8_t* bits, uint8_t* bytes) {
  int len_bits = SRSRAN_BCH_PAYLOAD_LEN;
  int len_bytes = len_bits / 8;
  for (int i = 0; i < len_bytes; ++i) {
    uint8_t byte = 0;
    for (int j = 0; j < 8; ++j) {
      byte <<= 1;                    // 左移一位
      byte |= bits[i * 8 + j];       // 加上当前比特
    }
    bytes[i] = byte;
  }
}
