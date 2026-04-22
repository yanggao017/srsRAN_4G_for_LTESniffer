#include "srsran/common/band_helper.h"
#include "srsran/radio/radio.h"
#include "srsue/hdr/phy/nr/cell_search.h"

extern "C" {
#include "srsran/phy/ue/ue_sync_nr.h"
}

#include <getopt.h>
#include <liquid/liquid.h>
#include <pthread.h>
#include <signal.h>
#include <sys/time.h>
#include <yaml-cpp/yaml.h>

#include <algorithm>
#include <cmath>
#include <complex>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <fstream>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

#define RESAMPLE_WORKER_NUM 8
#define TARGET_STOPBAND_SUPPRESSION_DB 60.0f
#define NR_FAILURE -1
#define NR_SUCCESS 0

enum class tx_mode_t {
  sync_and_inject,
  loop_after_sync,
};

struct ssb_tx_cfg_t {
  std::string rf_args;
  std::string device_name = "auto";
  std::string rf_log_level = "info";
  std::string inject_file;

  double ssb_freq_hz = 0.0;
  double tx_freq_hz = 0.0;
  double srate_hz = 23.04e6;
  double srsran_srate_hz = 23.04e6;
  double tx_time_calibration = 0.0;
  float  rx_gain = 60.0f;
  float  min_rx_gain = 0.0f;
  float  max_rx_gain = 80.0f;
  float  tx_gain = 60.0f;
  float  freq_offset = 0.0f;
  float  pbch_dmrs_thr = 0.5f;
  float  cfo_alpha = 0.1f;
  bool   disable_cfo = false;

  uint32_t buffer_size = 0;
  uint32_t nof_carriers = 1;
  uint32_t nof_antennas = 1;
  uint32_t ssb_period_ms = 20;
  uint32_t tx_sfn_phase = 0;
  uint32_t nof_trials = 2000;
  uint32_t tx_submit_advance_us = 15000;
  int32_t  inject_file_ssb_idx = 0;
  int32_t  target_ssb_idx = 0;
  tx_mode_t tx_mode = tx_mode_t::loop_after_sync;
  bool      tx_debug = true;
  srsran_subcarrier_spacing_t ssb_scs = srsran_subcarrier_spacing_30kHz;
};

struct tx_event_t {
  srsran_timestamp_t timestamp = {};
  uint32_t           sfn = 0;
  uint32_t           sf_idx = 0;
  float              delay_us = 0.0f;
};

static ssb_tx_cfg_t g_cfg;
static std::shared_ptr<srsran::radio> g_radio;
static srslog::basic_logger* g_logger = nullptr;

static cf_t* g_rx_buffer = nullptr;
static cf_t* g_search_rx_buffer = nullptr;
static cf_t* g_msg_buffer[SRSRAN_MAX_CHANNELS] = {};

static pthread_t g_rx_thread;
static pthread_t g_tx_thread;
static pthread_mutex_t g_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t g_cond = PTHREAD_COND_INITIALIZER;
static std::deque<tx_event_t> g_tx_events;
static bool       g_start_ready = false;
static tx_event_t g_start_event = {};
static volatile sig_atomic_t g_go_exit = 0;

static srsran_ue_sync_nr_t g_ue_sync_nr = {};
static srsran_ue_sync_nr_outcome_t g_outcome = {};
static srsran::rf_buffer_t g_sync_rf_buffer = {};
static resampler_kit g_resampler[RESAMPLE_WORKER_NUM] = {};
static bool g_resample_needed = false;
static uint32_t g_pre_resampling_sf_sz = 0;
static uint32_t g_slot_sz = 0;
static uint32_t g_pre_resampling_slot_sz = 0;

static srsran_ssb_pattern_t get_ssb_pattern_from_cfg()
{
  srsran::srsran_band_helper bands;
  uint16_t band = bands.get_band_from_dl_freq_Hz_and_scs(g_cfg.ssb_freq_hz, g_cfg.ssb_scs);
  srsran_assert(band != UINT16_MAX, "Invalid NR band for configured SSB frequency");
  return bands.get_ssb_pattern(band, g_cfg.ssb_scs);
}

static srsran_duplex_mode_t get_duplex_mode_from_cfg()
{
  srsran::srsran_band_helper bands;
  uint16_t band = bands.get_band_from_dl_freq_Hz_and_scs(g_cfg.ssb_freq_hz, g_cfg.ssb_scs);
  srsran_assert(band != UINT16_MAX, "Invalid NR band for configured SSB frequency");
  return bands.get_duplex_mode(band);
}

static uint32_t ssb_period_frames()
{
  return std::max(1u, g_cfg.ssb_period_ms / 10);
}

static bool is_target_ssb_occasion(const srsran_ue_sync_nr_outcome_t& outcome)
{
  if (!outcome.in_sync) {
    return false;
  }

  uint32_t half_frame = outcome.sf_idx / (SRSRAN_NOF_SF_X_FRAME / 2);
  uint32_t ssb_sf_idx =
    srsran_ssb_candidate_sf_idx(&g_ue_sync_nr.ssb, g_ue_sync_nr.ssb_idx, half_frame > 0);
  if (outcome.sf_idx != ssb_sf_idx) {
    return false;
  }

  if (g_cfg.ssb_period_ms >= 10 && half_frame != 0) {
    return false;
  }

  uint32_t period_frames = ssb_period_frames();
  return (outcome.sfn % period_frames) == (g_cfg.tx_sfn_phase % period_frames);
}

static void sig_int_handler(int)
{
  g_go_exit = 1;
  pthread_cond_broadcast(&g_cond);
}

static int64_t ts_to_us(const srsran_timestamp_t& ts)
{
  return (int64_t)ts.full_secs * 1000000LL + (int64_t)llround(ts.frac_secs * 1e6);
}

static int64_t rf_now_us()
{
  time_t secs = 0;
  double frac = 0.0;
  srsran_rf_get_time(&g_radio->rf_devices[0], &secs, &frac);
  return (int64_t)secs * 1000000LL + (int64_t)llround(frac * 1e6);
}

static bool start_ready()
{
  pthread_mutex_lock(&g_mutex);
  bool ready = g_start_ready;
  pthread_mutex_unlock(&g_mutex);
  return ready;
}

static void timestamp_add_signed(srsran_timestamp_t* ts, double seconds)
{
  if (seconds >= 0.0) {
    srsran_timestamp_add(ts, 0, seconds);
  } else {
    srsran_timestamp_sub(ts, 0, -seconds);
  }
}

static int32_t get_inject_file_ssb_offset_samples()
{
  if (g_cfg.inject_file_ssb_idx < 0) {
    return 0;
  }

  uint32_t live_offset = srsran_ssb_candidate_sf_offset(&g_ue_sync_nr.ssb, g_ue_sync_nr.ssb_idx);
  uint32_t file_offset = srsran_ssb_candidate_sf_offset(&g_ue_sync_nr.ssb, (uint32_t)g_cfg.inject_file_ssb_idx);
  return (int32_t)live_offset - (int32_t)file_offset;
}

static bool loop_after_sync_mode()
{
  return g_cfg.tx_mode == tx_mode_t::loop_after_sync;
}

static const char* tx_mode_to_str(tx_mode_t mode)
{
  return mode == tx_mode_t::loop_after_sync ? "loop_after_sync" : "sync_and_inject";
}

static int radio_recv_callback(void* ptr, cf_t** buffer, uint32_t nsamples, srsran_timestamp_t* ts)
{
  if (ptr == nullptr || buffer == nullptr || ts == nullptr) {
    return SRSRAN_ERROR_INVALID_INPUTS;
  }

  srsran::radio* radio = static_cast<srsran::radio*>(ptr);
  cf_t*          buffer_ptr[SRSRAN_MAX_CHANNELS] = {};
  buffer_ptr[0] = buffer[0];
  srsran::rf_buffer_t rf_buffer(buffer_ptr, nsamples);
  srsran::rf_timestamp_t rf_timestamp;

  bool ret = radio->rx_now(rf_buffer, rf_timestamp);
  *ts = rf_timestamp.get(0);
  return ret ? SRSRAN_SUCCESS : SRSRAN_ERROR;
}

static SRSRAN_AGC_CALLBACK(radio_set_rx_gain_wrapper)
{
  printf("[AGC gain adj] new rx gain: %f\n", gain_db);
  static_cast<srsran::radio*>(h)->set_rx_gain(gain_db);
}

static void read_file_to_buffer(const std::string& file_name)
{
  for (cf_t*& buf : g_msg_buffer) {
    buf = srsran_vec_cf_malloc(g_cfg.buffer_size);
    if (buf == nullptr) {
      throw std::runtime_error("failed to allocate TX buffer");
    }
    srsran_vec_cf_zero(buf, g_cfg.buffer_size);
  }

  std::ifstream file(file_name, std::ios::binary);
  if (!file) {
    throw std::runtime_error("failed to open inject_file: " + file_name);
  }

  file.read(reinterpret_cast<char*>(g_msg_buffer[0]), g_cfg.buffer_size * sizeof(cf_t));
  std::streamsize got = file.gcount();
  if (got <= 0) {
    throw std::runtime_error("inject_file is empty: " + file_name);
  }
  if ((uint32_t)got < g_cfg.buffer_size * sizeof(cf_t)) {
    printf("Warning: inject_file shorter than buffer_size, read %ld bytes\n", (long)got);
  }
}

static ssb_tx_cfg_t load_cfg(const std::string& file_name)
{
  YAML::Node root = YAML::LoadFile(file_name);
  YAML::Node node = root["usrp_setting_0"];
  if (!node) {
    throw std::runtime_error("missing usrp_setting_0 in config");
  }

  ssb_tx_cfg_t cfg;
  if (node["rf_args"]) {
    cfg.rf_args = node["rf_args"].as<std::string>();
  }
  if (node["device_name"]) {
    cfg.device_name = node["device_name"].as<std::string>();
  }
  if (node["rf_log_level"]) {
    cfg.rf_log_level = node["rf_log_level"].as<std::string>();
  }
  if (node["inject_file"]) {
    cfg.inject_file = node["inject_file"].as<std::string>();
  }
  if (node["tx_mode"]) {
    std::string mode = node["tx_mode"].as<std::string>();
    if (mode == "loop_after_sync") {
      cfg.tx_mode = tx_mode_t::loop_after_sync;
    } else if (mode == "sync_and_inject") {
      cfg.tx_mode = tx_mode_t::sync_and_inject;
    } else {
      throw std::runtime_error("tx_mode must be loop_after_sync or sync_and_inject");
    }
  }
  if (node["ssb_freq"]) {
    cfg.ssb_freq_hz = node["ssb_freq"].as<double>();
  }
  if (node["tx_freq"]) {
    cfg.tx_freq_hz = node["tx_freq"].as<double>();
  }
  if (node["buffer_size"]) {
    cfg.buffer_size = node["buffer_size"].as<uint32_t>();
  }
  if (node["tx_time_calibration"]) {
    cfg.tx_time_calibration = node["tx_time_calibration"].as<double>();
  }
  if (node["ssb_period_ms"]) {
    cfg.ssb_period_ms = node["ssb_period_ms"].as<uint32_t>();
  }
  if (node["tx_sfn_phase"]) {
    cfg.tx_sfn_phase = node["tx_sfn_phase"].as<uint32_t>();
  }
  if (node["tx_submit_advance_us"]) {
    cfg.tx_submit_advance_us = node["tx_submit_advance_us"].as<uint32_t>();
  }
  if (node["tx_debug"]) {
    cfg.tx_debug = node["tx_debug"].as<bool>();
  }
  if (node["rx_gain"]) {
    cfg.rx_gain = node["rx_gain"].as<float>();
  }
  if (node["min_rx_gain"]) {
    cfg.min_rx_gain = node["min_rx_gain"].as<float>();
  }
  if (node["max_rx_gain"]) {
    cfg.max_rx_gain = node["max_rx_gain"].as<float>();
  }
  if (node["tx_gain"]) {
    cfg.tx_gain = node["tx_gain"].as<float>();
  }
  if (node["srate_hz"]) {
    cfg.srate_hz = node["srate_hz"].as<double>();
  }
  if (node["srsran_srate_hz"]) {
    cfg.srsran_srate_hz = node["srsran_srate_hz"].as<double>();
  }
  if (node["nof_carriers"]) {
    cfg.nof_carriers = node["nof_carriers"].as<uint32_t>();
  }
  if (node["nof_antennas"]) {
    cfg.nof_antennas = node["nof_antennas"].as<uint32_t>();
  }
  if (node["freq_offset"]) {
    cfg.freq_offset = node["freq_offset"].as<float>();
  }
  if (node["pbch_dmrs_thr"]) {
    cfg.pbch_dmrs_thr = node["pbch_dmrs_thr"].as<float>();
  }
  if (node["cfo_alpha"]) {
    cfg.cfo_alpha = node["cfo_alpha"].as<float>();
  }
  if (node["disable_cfo"]) {
    cfg.disable_cfo = node["disable_cfo"].as<bool>();
  }
  if (node["scs_index"]) {
    cfg.ssb_scs = (srsran_subcarrier_spacing_t)node["scs_index"].as<int>();
  }
  if (node["nof_trials"]) {
    cfg.nof_trials = node["nof_trials"].as<uint32_t>();
  }
  if (node["inject_file_ssb_idx"]) {
    cfg.inject_file_ssb_idx = node["inject_file_ssb_idx"].as<int32_t>();
  }
  if (node["target_ssb_idx"]) {
    cfg.target_ssb_idx = node["target_ssb_idx"].as<int32_t>();
  }

  if (cfg.tx_freq_hz == 0.0) {
    cfg.tx_freq_hz = cfg.ssb_freq_hz;
  }
  if (cfg.ssb_freq_hz == 0.0 || cfg.buffer_size == 0 || cfg.inject_file.empty()) {
    throw std::runtime_error("ssb_freq, buffer_size and inject_file must be configured");
  }

  return cfg;
}

static void reset_sync_to_find_after_wrong_ssb_idx()
{
  g_ue_sync_nr.state = SRSRAN_UE_SYNC_NR_STATE_FIND;
  g_ue_sync_nr.next_rf_sample_offset = 0;
  g_ue_sync_nr.sf_idx = 0;
  g_ue_sync_nr.sfn = 0;
  g_ue_sync_nr.avg_delay_us = 0.0f;
}

static srsue::nr::cell_search::ret_t search_cell(srsran_ssb_pattern_t ssb_pattern,
                                                 srsran_duplex_mode_t duplex_mode)
{
  srslog::basic_logger& logger = *g_logger;
  srsue::nr::cell_search searcher(logger);
  srsue::nr::cell_search::args_t search_args = {};
  search_args.max_srate_hz = 92.16e6;
  search_args.ssb_min_scs = srsran_subcarrier_spacing_15kHz;
  searcher.init(search_args);

  srsue::nr::cell_search::cfg_t search_cfg = {};
  search_cfg.srate_hz = g_cfg.srsran_srate_hz;
  search_cfg.center_freq_hz = g_cfg.ssb_freq_hz;
  search_cfg.ssb_freq_hz = g_cfg.ssb_freq_hz;
  search_cfg.ssb_scs = g_cfg.ssb_scs;
  search_cfg.ssb_pattern = ssb_pattern;
  search_cfg.duplex_mode = duplex_mode;

  if (!searcher.start(search_cfg)) {
    throw std::runtime_error("failed to start NR cell search");
  }

  const uint32_t slots_per_sf = SRSRAN_NOF_SLOTS_PER_SF_NR(g_cfg.ssb_scs);
  g_pre_resampling_slot_sz = (uint32_t)(g_cfg.srate_hz / 1000.0 / slots_per_sf);
  g_slot_sz = (uint32_t)(g_cfg.srsran_srate_hz / 1000.0 / slots_per_sf);
  g_pre_resampling_sf_sz = slots_per_sf * g_pre_resampling_slot_sz;

  g_search_rx_buffer = srsran_vec_cf_malloc(g_pre_resampling_slot_sz);
  g_rx_buffer = srsran_vec_cf_malloc(g_pre_resampling_sf_sz);
  if (g_search_rx_buffer == nullptr || g_rx_buffer == nullptr) {
    throw std::runtime_error("failed to allocate RX buffers");
  }

  g_resample_needed = fabs(g_cfg.srsran_srate_hz - g_cfg.srate_hz) >= 0.1;
  msresamp_crcf search_resampler = nullptr;
  std::vector<std::complex<float>> temp_in;
  std::vector<std::complex<float>> temp_out;
  if (g_resample_needed) {
    float ratio = (float)(g_cfg.srsran_srate_hz / g_cfg.srate_hz);
    search_resampler = msresamp_crcf_create(ratio, TARGET_STOPBAND_SUPPRESSION_DB);
    uint32_t temp_in_sz = g_pre_resampling_slot_sz + (uint32_t)ceilf(msresamp_crcf_get_delay(search_resampler)) + 10;
    temp_in.resize(temp_in_sz);
    temp_out.resize((uint32_t)(temp_in_sz * ratio * 2));
  }

  srsran::rf_buffer_t rf_buffer = {};
  rf_buffer.set_nof_samples(g_pre_resampling_slot_sz);
  rf_buffer.set(0, g_search_rx_buffer);

  srsue::nr::cell_search::ret_t ret = {};
  ret.result = srsue::nr::cell_search::ret_t::CELL_NOT_FOUND;
  for (uint32_t trial = 0; trial < g_cfg.nof_trials && !g_go_exit; trial++) {
    srsran_vec_cf_zero(g_rx_buffer, g_pre_resampling_sf_sz);
    srsran::rf_timestamp_t timestamp;
    if (!g_radio->rx_now(rf_buffer, timestamp)) {
      throw std::runtime_error("radio rx_now failed during cell search");
    }

    if (g_resample_needed) {
      for (uint32_t i = 0; i < temp_in.size(); i++) {
        temp_in[i] = i < g_pre_resampling_slot_sz ? g_search_rx_buffer[i] : cf_t{};
      }
      uint32_t actual_sz = 0;
      msresamp_crcf_execute(search_resampler, temp_in.data(), temp_in.size(), temp_out.data(), &actual_sz);
      for (uint32_t i = 0; i < std::min(actual_sz, g_slot_sz); i++) {
        g_rx_buffer[i] = cf_t{temp_out[i].real(), temp_out[i].imag()};
      }
    } else {
      srsran_vec_cf_copy(g_rx_buffer, g_search_rx_buffer, g_pre_resampling_slot_sz);
    }

    ret = searcher.run_slot(g_rx_buffer, g_slot_sz);
    if (ret.result == srsue::nr::cell_search::ret_t::CELL_FOUND) {
      break;
    }
  }

  if (search_resampler != nullptr) {
    msresamp_crcf_destroy(search_resampler);
  }

  return ret;
}

static void queue_tx_event(const srsran_ue_sync_nr_outcome_t& outcome)
{
  tx_event_t event = {};
  event.timestamp = outcome.timestamp;
  event.sfn = outcome.sfn;
  event.sf_idx = outcome.sf_idx;
  event.delay_us = outcome.delay_us;

  srsran_timestamp_add(&event.timestamp, 0, (double)g_cfg.ssb_period_ms * 1e-3);
  srsran_timestamp_add(&event.timestamp, 0, g_cfg.tx_time_calibration);
  int32_t ssb_offset_samples = get_inject_file_ssb_offset_samples();
  timestamp_add_signed(&event.timestamp, (double)ssb_offset_samples / g_cfg.srate_hz);

  printf("[Rx] queue TX: live_ssb_idx=%u file_ssb_idx=%d ssb_offset=%d samples rx_ts=%lld.%06d tx_ts=%lld.%06d\n",
         g_ue_sync_nr.ssb_idx,
         g_cfg.inject_file_ssb_idx,
         ssb_offset_samples,
         (long long)outcome.timestamp.full_secs,
         (int)(outcome.timestamp.frac_secs * 1e6),
         (long long)event.timestamp.full_secs,
         (int)(event.timestamp.frac_secs * 1e6));

  pthread_mutex_lock(&g_mutex);
  if (loop_after_sync_mode()) {
    if (!g_start_ready) {
      g_start_event = event;
      g_start_ready = true;
    }
    pthread_cond_broadcast(&g_cond);
  } else {
    g_tx_events.push_back(event);
    pthread_cond_signal(&g_cond);
  }
  pthread_mutex_unlock(&g_mutex);
}

static void* tx_thread_func(void*)
{
  bool start_of_burst = true;
  bool end_of_burst = true;
  bool blocking = true;

  srsran_rf_set_tx_srate(&g_radio->rf_devices[0], g_cfg.srate_hz);
  srsran_rf_set_tx_gain(&g_radio->rf_devices[0], g_cfg.tx_gain);
  srsran_rf_set_tx_freq(&g_radio->rf_devices[0], 0, g_cfg.tx_freq_hz);

  while (!g_go_exit) {
    pthread_mutex_lock(&g_mutex);
    while (g_tx_events.empty() && !g_go_exit) {
      pthread_cond_wait(&g_cond, &g_mutex);
    }
    if (g_go_exit) {
      pthread_mutex_unlock(&g_mutex);
      break;
    }

    tx_event_t event = g_tx_events.front();
    g_tx_events.pop_front();
    pthread_mutex_unlock(&g_mutex);

    int ret = srsran_rf_send_timed_multi(&g_radio->rf_devices[0],
                                         (void**)g_msg_buffer,
                                         g_cfg.buffer_size,
                                         event.timestamp.full_secs,
                                         event.timestamp.frac_secs,
                                         blocking,
                                         start_of_burst,
                                         end_of_burst);
    if (ret != (int)g_cfg.buffer_size) {
      printf("[Tx] failed: sent %d/%u samples\n", ret, g_cfg.buffer_size);
    } else {
      printf("[Tx] sent one SSB event for next period: ref_sfn=%u ref_sf_idx=%u tx_ts=%lld.%06d delay_us=%.3f\n",
             event.sfn,
             event.sf_idx,
             (long long)event.timestamp.full_secs,
             (int)(event.timestamp.frac_secs * 1e6),
             event.delay_us);
    }
  }

  return nullptr;
}

static void sleep_until_tx_window(const srsran_timestamp_t& ts)
{
  const int64_t target_lead_us = (int64_t)g_cfg.tx_submit_advance_us;
  while (!g_go_exit) {
    const int64_t lead_us = ts_to_us(ts) - rf_now_us();
    if (lead_us <= target_lead_us) {
      return;
    }
    usleep((useconds_t)std::min<int64_t>(5000, lead_us - target_lead_us));
  }
}

static void run_periodic_tx_loop(tx_event_t start)
{
  bool start_of_burst = true;
  bool end_of_burst = true;
  bool blocking = true;
  const double period_s = (double)g_cfg.ssb_period_ms * 1e-3;

  srsran_rf_set_tx_srate(&g_radio->rf_devices[0], g_cfg.srate_hz);
  srsran_rf_set_tx_gain(&g_radio->rf_devices[0], g_cfg.tx_gain);
  srsran_rf_set_tx_freq(&g_radio->rf_devices[0], 0, g_cfg.tx_freq_hz);

  srsran_timestamp_t tx_ts = start.timestamp;

  printf("[Tx] periodic injection started: ref_sfn=%u ref_sf_idx=%u first_ts=%lld.%06d period_ms=%u lead=%.3f ms\n",
         start.sfn,
         start.sf_idx,
         (long long)tx_ts.full_secs,
         (int)(tx_ts.frac_secs * 1e6),
         g_cfg.ssb_period_ms,
         (double)(ts_to_us(tx_ts) - rf_now_us()) / 1000.0);

  while (!g_go_exit) {
    int64_t now_before_sleep_us = rf_now_us();
    int64_t lead_before_sleep_us = ts_to_us(tx_ts) - now_before_sleep_us;
    if (g_cfg.tx_debug) {
      printf("[Tx dbg] before sleep target_ts=%lld.%06d rf_now=%lld.%06lld lead=%.3f ms submit_advance=%.3f ms\n",
             (long long)tx_ts.full_secs,
             (int)(tx_ts.frac_secs * 1e6),
             (long long)(now_before_sleep_us / 1000000LL),
             (long long)(llabs(now_before_sleep_us % 1000000LL)),
             (double)lead_before_sleep_us / 1000.0,
             (double)g_cfg.tx_submit_advance_us / 1000.0);
    }

    sleep_until_tx_window(tx_ts);
    if (g_go_exit) {
      break;
    }

    int64_t now_before_send_us = rf_now_us();
    int64_t lead_before_send_us = ts_to_us(tx_ts) - now_before_send_us;
    if (g_cfg.tx_debug) {
      printf("[Tx dbg] before send  target_ts=%lld.%06d rf_now=%lld.%06lld lead=%.3f ms nsamples=%u duration=%.3f ms\n",
             (long long)tx_ts.full_secs,
             (int)(tx_ts.frac_secs * 1e6),
             (long long)(now_before_send_us / 1000000LL),
             (long long)(llabs(now_before_send_us % 1000000LL)),
             (double)lead_before_send_us / 1000.0,
             g_cfg.buffer_size,
             (double)g_cfg.buffer_size * 1000.0 / g_cfg.srate_hz);
    }

    int ret = srsran_rf_send_timed_multi(&g_radio->rf_devices[0],
                                         (void**)g_msg_buffer,
                                         g_cfg.buffer_size,
                                         tx_ts.full_secs,
                                         tx_ts.frac_secs,
                                         blocking,
                                         start_of_burst,
                                         end_of_burst);
    if (ret != (int)g_cfg.buffer_size) {
      printf("[Tx] failed: sent %d/%u samples\n", ret, g_cfg.buffer_size);
    } else if (g_cfg.tx_debug) {
      int64_t now_after_send_us = rf_now_us();
      printf("[Tx dbg] after send   target_ts=%lld.%06d rf_now=%lld.%06lld lead=%.3f ms ret=%d\n",
             (long long)tx_ts.full_secs,
             (int)(tx_ts.frac_secs * 1e6),
             (long long)(now_after_send_us / 1000000LL),
             (long long)(llabs(now_after_send_us % 1000000LL)),
             (double)(ts_to_us(tx_ts) - now_after_send_us) / 1000.0,
             ret);
    }

    srsran_timestamp_add(&tx_ts, 0, period_s);
  }
}

static void* rx_thread_func(void*)
{
  while (!g_go_exit && !(loop_after_sync_mode() && start_ready())) {
    struct timeval rx_time = {};
    if (srsran_ue_sync_nr_zerocopy_twinrx_nrscope(&g_ue_sync_nr,
                                                  g_sync_rf_buffer.to_cf_t(),
                                                  &g_outcome,
                                                  g_resampler,
                                                  g_resample_needed,
                                                  RESAMPLE_WORKER_NUM,
                                                  rx_time) < SRSRAN_SUCCESS) {
      printf("[Rx] sync failed\n");
      continue;
    }

    if (!is_target_ssb_occasion(g_outcome)) {
      continue;
    }

    if (g_cfg.target_ssb_idx >= 0 && g_ue_sync_nr.ssb_idx != (uint32_t)g_cfg.target_ssb_idx) {
      if (is_target_ssb_occasion(g_outcome)) {
        printf("[Rx] SSB index %u != target %d on target SSB occasion, rx_ts=%lld.%06d, reset sync to FIND\n",
               g_ue_sync_nr.ssb_idx,
               g_cfg.target_ssb_idx,
               (long long)g_outcome.timestamp.full_secs,
               (int)(g_outcome.timestamp.frac_secs * 1e6));
      }
      reset_sync_to_find_after_wrong_ssb_idx();
      continue;
    }

    printf("[Rx] target SSB occasion: sfn=%u sf_idx=%u ssb_idx=%u rx_ts=%lld.%06d\n",
           g_outcome.sfn,
           g_outcome.sf_idx,
           g_ue_sync_nr.ssb_idx,
           (long long)g_outcome.timestamp.full_secs,
           (int)(g_outcome.timestamp.frac_secs * 1e6));
    queue_tx_event(g_outcome);
    if (loop_after_sync_mode()) {
      break;
    }
  }

  return nullptr;
}

static void init_sync(uint32_t pci, srsran_ssb_pattern_t ssb_pattern, srsran_duplex_mode_t duplex_mode)
{
  srsran_ue_sync_nr_args_t sync_args = {};
  sync_args.max_srate_hz = 92.16e6;
  sync_args.min_scs = srsran_subcarrier_spacing_15kHz;
  sync_args.nof_rx_channels = 1;
  sync_args.disable_cfo = g_cfg.disable_cfo;
  sync_args.pbch_dmrs_thr = g_cfg.pbch_dmrs_thr;
  sync_args.cfo_alpha = g_cfg.cfo_alpha;
  sync_args.recv_obj = g_radio.get();
  sync_args.recv_callback = radio_recv_callback;

  g_ue_sync_nr.resample_ratio = (float)(g_cfg.srsran_srate_hz / g_cfg.srate_hz);
  if (srsran_ue_sync_nr_init(&g_ue_sync_nr, &sync_args) < SRSRAN_SUCCESS) {
    throw std::runtime_error("failed to init NR UE sync");
  }

  srsran_ssb_cfg_t ssb_cfg = {};
  ssb_cfg.srate_hz = g_cfg.srsran_srate_hz;
  ssb_cfg.center_freq_hz = g_cfg.ssb_freq_hz;
  ssb_cfg.ssb_freq_hz = g_cfg.ssb_freq_hz;
  ssb_cfg.scs = g_cfg.ssb_scs;
  ssb_cfg.pattern = ssb_pattern;
  ssb_cfg.duplex_mode = duplex_mode;
  ssb_cfg.periodicity_ms = g_cfg.ssb_period_ms;

  srsran_ue_sync_nr_cfg_t sync_cfg = {};
  sync_cfg.N_id = pci;
  sync_cfg.ssb = ssb_cfg;
  if (srsran_ue_sync_nr_set_cfg(&g_ue_sync_nr, &sync_cfg) < SRSRAN_SUCCESS) {
    throw std::runtime_error("failed to configure NR UE sync");
  }
  if (g_cfg.inject_file_ssb_idx >= 0 && (uint32_t)g_cfg.inject_file_ssb_idx >= g_ue_sync_nr.ssb.Lmax) {
    throw std::runtime_error("inject_file_ssb_idx is outside SSB Lmax");
  }

  srsran_ue_sync_nr_start_agc(&g_ue_sync_nr,
                              radio_set_rx_gain_wrapper,
                              g_cfg.rx_gain,
                              g_cfg.min_rx_gain,
                              g_cfg.max_rx_gain);

  if (g_resample_needed) {
    prepare_resampler(g_resampler,
                      (float)(g_cfg.srsran_srate_hz / g_cfg.srate_hz),
                      g_pre_resampling_sf_sz,
                      RESAMPLE_WORKER_NUM);
  }

  g_sync_rf_buffer = srsran::rf_buffer_t(g_rx_buffer, g_pre_resampling_sf_sz);
}

static void init_radio()
{
  srsran::rf_args_t rf_args = {};
  rf_args.device_args = g_cfg.rf_args;
  rf_args.device_name = g_cfg.device_name;
  rf_args.log_level = g_cfg.rf_log_level;
  rf_args.srate_hz = g_cfg.srate_hz;
  rf_args.srsran_srate_hz = g_cfg.srsran_srate_hz;
  rf_args.rx_gain = g_cfg.rx_gain;
  rf_args.tx_gain = g_cfg.tx_gain;
  rf_args.dl_freq = g_cfg.ssb_freq_hz;
  rf_args.freq_offset = g_cfg.freq_offset;
  rf_args.nof_carriers = g_cfg.nof_carriers;
  rf_args.nof_antennas = g_cfg.nof_antennas;

  g_radio = std::make_shared<srsran::radio>();
  if (g_radio->init(rf_args, nullptr) != SRSRAN_SUCCESS) {
    throw std::runtime_error("failed to init radio");
  }

  g_radio->set_rx_srate(g_cfg.srate_hz);
  g_radio->set_tx_srate(g_cfg.srate_hz);
  g_radio->set_rx_freq(0, g_cfg.ssb_freq_hz);
  g_radio->set_tx_freq(0, g_cfg.tx_freq_hz);
  g_radio->set_rx_gain(g_cfg.rx_gain);
  g_radio->set_tx_gain(g_cfg.tx_gain);
}

static void usage(const char* prog)
{
  printf("Usage: %s [-c config_file]\n", prog);
}

int main(int argc, char** argv)
{
  std::string config_file = "../../../nrscope/config/config.yaml";
  int opt = 0;
  while ((opt = getopt(argc, argv, "c:h")) != -1) {
    switch (opt) {
      case 'c':
        config_file = optarg;
        break;
      case 'h':
      default:
        usage(argv[0]);
        return opt == 'h' ? NR_SUCCESS : NR_FAILURE;
    }
  }

  try {
    signal(SIGINT, sig_int_handler);
    signal(SIGTERM, sig_int_handler);
    srslog::init();
    g_logger = &srslog::fetch_basic_logger("SSB-ENB");

    g_cfg = load_cfg(config_file);
    printf("NR SSB TX injector: ssb_freq=%.3f MHz tx_freq=%.3f MHz ssb_period=%u ms phase=%u calibration=%.6f ms tx_mode=%s\n",
           g_cfg.ssb_freq_hz / 1e6,
           g_cfg.tx_freq_hz / 1e6,
           g_cfg.ssb_period_ms,
           g_cfg.tx_sfn_phase,
           g_cfg.tx_time_calibration * 1e3,
           tx_mode_to_str(g_cfg.tx_mode));

    read_file_to_buffer(g_cfg.inject_file);
    init_radio();

    srsran_ssb_pattern_t ssb_pattern = get_ssb_pattern_from_cfg();
    srsran_duplex_mode_t duplex_mode = get_duplex_mode_from_cfg();
    srsue::nr::cell_search::ret_t search_ret = search_cell(ssb_pattern, duplex_mode);
    if (search_ret.result != srsue::nr::cell_search::ret_t::CELL_FOUND) {
      printf("No cell found at configured SSB frequency.\n");
      return NR_SUCCESS;
    }
    printf("Cell found: N_id=%u. Starting RX%s.\n",
           search_ret.ssb_res.N_id,
           loop_after_sync_mode() ? " once" : "/TX threads");

    init_sync(search_ret.ssb_res.N_id, ssb_pattern, duplex_mode);

    if (!loop_after_sync_mode()) {
      if (pthread_create(&g_tx_thread, nullptr, tx_thread_func, nullptr) != 0) {
        throw std::runtime_error("failed to create TX thread");
      }
    }
    if (pthread_create(&g_rx_thread, nullptr, rx_thread_func, nullptr) != 0) {
      throw std::runtime_error("failed to create RX thread");
    }

    if (loop_after_sync_mode()) {
      tx_event_t start = {};
      bool start_valid = false;
      pthread_mutex_lock(&g_mutex);
      while (!g_start_ready && !g_go_exit) {
        pthread_cond_wait(&g_cond, &g_mutex);
      }
      if (g_start_ready) {
        start = g_start_event;
        start_valid = true;
      }
      pthread_mutex_unlock(&g_mutex);

      if (start_valid || g_go_exit) {
        srsran_rf_stop_rx_stream(&g_radio->rf_devices[0]);
      }

      pthread_join(g_rx_thread, nullptr);

      if (!start_valid || g_go_exit) {
        printf("No SSB sync event captured.\n");
        if (g_radio) {
          g_radio->stop();
        }
        return NR_SUCCESS;
      }

      run_periodic_tx_loop(start);
    } else {
      pthread_join(g_rx_thread, nullptr);
      pthread_join(g_tx_thread, nullptr);
    }
    if (g_radio) {
      g_radio->stop();
    }
  } catch (const std::exception& e) {
    if (g_radio) {
      g_radio->stop();
    }
    std::cerr << "Error: " << e.what() << std::endl;
    return NR_FAILURE;
  }

  return NR_SUCCESS;
}
