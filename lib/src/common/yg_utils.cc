
#include "srsran/common/yg_utils.h"

// 打印函数
void print_srsran_carrier_nr(const srsran_carrier_nr_t* carrier)
{
    if (carrier == NULL) {
        printf("Error: carrier pointer is NULL\n");
        return;
    }
    const char* scs_str = "Unknown";
    switch (carrier->scs) {
        case srsran_subcarrier_spacing_15kHz:  scs_str = "15 kHz";  break;
        case srsran_subcarrier_spacing_30kHz:  scs_str = "30 kHz";  break;
        case srsran_subcarrier_spacing_60kHz:  scs_str = "60 kHz";  break;
        case srsran_subcarrier_spacing_120kHz: scs_str = "120 kHz"; break;
        case srsran_subcarrier_spacing_240kHz: scs_str = "240 kHz"; break;        
        default: scs_str = "Invalid"; break;
    }

    printf("=== srsran_carrier_nr_t ===\n");
    printf("PCI: %u\n", carrier->pci);
    printf("DL Center Frequency: %.0f Hz (%.1f MHz)\n", carrier->dl_center_frequency_hz, carrier->dl_center_frequency_hz / 1e6);
    printf("UL Center Frequency: %.0f Hz (%.1f MHz)\n", carrier->ul_center_frequency_hz, carrier->ul_center_frequency_hz / 1e6);
    printf("SSB Center Frequency: %.0f Hz (%.1f MHz)\n", carrier->ssb_center_freq_hz, carrier->ssb_center_freq_hz / 1e6);
    printf("Offset to Carrier (PRB): %u\n", carrier->offset_to_carrier);
    printf("Subcarrier Spacing (SCS): %s\n", scs_str);
    printf("Number of PRBs: %u\n", carrier->nof_prb);
    printf("Start PRB: %u\n", carrier->start);
    printf("Max MIMO Layers: %u\n", carrier->max_mimo_layers);
    printf("==========================\n");
}

void print_cfr_tx_cfg(const srsran_cfr_cfg_t* cfr_tx_cfg) {
    if (!cfr_tx_cfg) {
        printf("Null configuration pointer!\n");
        return;
    }
  
    // Print CFR configuration details
    printf("CFR Tx Configuration:\n");
    printf("  CFR Enable: %d\n", cfr_tx_cfg->cfr_enable);
    printf("  CFR Mode: %d\n", cfr_tx_cfg->cfr_mode);
    printf("  Symbol Bandwidth: %u FFT bins\n", cfr_tx_cfg->symbol_bw);
    printf("  Symbol Size: %u samples\n", cfr_tx_cfg->symbol_sz);
    printf("  Alpha (Clipping Algorithm Parameter): %.2f\n", cfr_tx_cfg->alpha);
    printf("  DC Subcarrier Consideration: %d\n", cfr_tx_cfg->dc_sc);
  
    // Print manual threshold if mode is SRSRAN_CFR_THR_MANUAL
    if (cfr_tx_cfg->cfr_mode == SRSRAN_CFR_THR_MANUAL) {
        printf("  Manual Threshold: %.2f\n", cfr_tx_cfg->manual_thr);
    }
  
    // Print parameters for SRSRAN_CFR_THR_AUTO_CMA and SRSRAN_CFR_THR_AUTO_EMA modes
    if (cfr_tx_cfg->cfr_mode == SRSRAN_CFR_THR_AUTO_CMA || cfr_tx_cfg->cfr_mode == SRSRAN_CFR_THR_AUTO_EMA) {
        printf("  Measure Output PAPR: %d\n", cfr_tx_cfg->measure_out_papr);
        printf("  Max PAPR (dB): %.2f\n", cfr_tx_cfg->max_papr_db);
        printf("  EMA Alpha for Power Calculation: %.2f\n", cfr_tx_cfg->ema_alpha);
    }
}
void print_cfr_t(const srsran_cfr_t* cfr) {
    if (!cfr) {
        printf("Null configuration pointer!\n");
        return;
    }
  
    // Print the CFR configuration details
    printf("CFR Configuration:\n");
  
    // Print the configuration from srsran_cfr_cfg_t
    printf("  CFR Enable: %d\n", cfr->cfg.cfr_enable);
    printf("  CFR Mode: %d\n", cfr->cfg.cfr_mode);
    printf("  Symbol Bandwidth: %u FFT bins\n", cfr->cfg.symbol_bw);
    printf("  Symbol Size: %u samples\n", cfr->cfg.symbol_sz);
    printf("  Alpha (Clipping Algorithm Parameter): %.2f\n", cfr->cfg.alpha);
    printf("  DC Subcarrier Consideration: %d\n", cfr->cfg.dc_sc);
  
    if (cfr->cfg.cfr_mode == SRSRAN_CFR_THR_MANUAL) {
        printf("  Manual Threshold: %.2f\n", cfr->cfg.manual_thr);
    }
  
    if (cfr->cfg.cfr_mode == SRSRAN_CFR_THR_AUTO_CMA || cfr->cfg.cfr_mode == SRSRAN_CFR_THR_AUTO_EMA) {
        printf("  Measure Output PAPR: %d\n", cfr->cfg.measure_out_papr);
        printf("  Max PAPR (dB): %.2f\n", cfr->cfg.max_papr_db);
        printf("  EMA Alpha for Power Calculation: %.2f\n", cfr->cfg.ema_alpha);
    }
  
    // Print additional fields of srsran_cfr_t
    printf("  Max PAPR (Linear): %.2f\n", cfr->max_papr_lin);
  
    // Print the status of the FFT and IFFT plans
    printf("  FFT Plan:\n");
    printf("    Size: %d\n", cfr->fft_plan.size);
    printf("    Forward: %d\n", cfr->fft_plan.forward);
    printf("    Mirror: %d\n", cfr->fft_plan.mirror);
    printf("    Mode: %d\n", cfr->fft_plan.mode);
  
    printf("  IFFT Plan:\n");
    printf("    Size: %d\n", cfr->ifft_plan.size);
    printf("    Forward: %d\n", cfr->ifft_plan.forward);
    printf("    Mirror: %d\n", cfr->ifft_plan.mirror);
    printf("    Mode: %d\n", cfr->ifft_plan.mode);
  
    // LPF (Low Pass Filter) Spectrum and Bandwidth
    printf("  LPF Bandwidth: %u\n", cfr->lpf_bw);
  
    // Power average information
    printf("  Input Power Average: %.2f\n", cfr->pwr_avg_in);
    printf("  Output Power Average: %.2f\n", cfr->pwr_avg_out);
  
    // Power Average buffers in SRSRAN_CFR_THR_AUTO_CMA mode
    printf("  CMA Count: %lu\n", cfr->cma_n);
}
void print_srsran_ofdm(const srsran_ofdm_t* ofdm) {
    if (!ofdm) {
        printf("Null configuration pointer!\n");
        return;
    }
  
    // Print basic fields
    printf("OFDM Configuration:\n");
    printf("max_prb: %u\n", ofdm->max_prb);
    printf("nof_symbols: %u\n", ofdm->nof_symbols);
    printf("nof_guards: %u\n", ofdm->nof_guards);
    printf("nof_re: %u\n", ofdm->nof_re);
    printf("slot_sz: %u\n", ofdm->slot_sz);
    printf("sf_sz: %u\n", ofdm->sf_sz);
  
    // mbsfn_subframe flag and related fields
    printf("mbsfn_subframe: %d\n", ofdm->mbsfn_subframe);
    printf("mbsfn_guard_len: %u\n", ofdm->mbsfn_guard_len);
    printf("nof_symbols_mbsfn: %u\n", ofdm->nof_symbols_mbsfn);
    printf("non_mbsfn_region: %u\n", ofdm->non_mbsfn_region);
  
    // window_offset_n
    printf("window_offset_n: %u\n", ofdm->window_offset_n);
  
  
  
    // Print tx_cfr (Tx CFR object)
    printf("tx_cfr:\n");
    // Assuming tx_cfr is a structure and we need to print its members, we print the relevant fields.
    // Example:
    // printf("  tx_cfr.field_name: %d\n", ofdm->tx_cfr.field_name);
    
    // Print OFDM configuration details (from srsran_ofdm_cfg_t)
    printf("OFDM Configuration (cfg):\n");
    printf("  nof_prb: %u\n", ofdm->cfg.nof_prb);
    printf("  Symbol size: %u\n", ofdm->cfg.symbol_sz);
    printf("  Cyclic Prefix: %d\n", ofdm->cfg.cp);
    printf("  Subframe type: %d\n", ofdm->cfg.sf_type);
    printf("  Normalize: %d\n", ofdm->cfg.normalize);
    printf("  Frequency Shift: %.2f\n", ofdm->cfg.freq_shift_f);
    printf("  RX Window Offset: %.2f\n", ofdm->cfg.rx_window_offset);
    printf("  Keep DC: %d\n", ofdm->cfg.keep_dc);
    printf("  Phase Compensation Hz: %.2f\n", ofdm->cfg.phase_compensation_hz);
  
    // Print CFR Tx Configuration
    printf("CFR Tx Configuration:\n");
    print_cfr_tx_cfg(&ofdm->cfg.cfr_tx_cfg);
    
    // Print DFT Plan details
    printf("DFT Plan Configuration:\n");
    printf("  init_size: %d\n", ofdm->fft_plan.init_size);
    printf("  size: %d\n", ofdm->fft_plan.size);
    printf("  is_guru: %d\n", ofdm->fft_plan.is_guru);
    printf("  forward: %d\n", ofdm->fft_plan.forward);
    printf("  mirror: %d\n", ofdm->fft_plan.mirror);
    printf("  db: %d\n", ofdm->fft_plan.db);
    printf("  norm: %d\n", ofdm->fft_plan.norm);
    printf("  dc: %d\n", ofdm->fft_plan.dc);
    printf("  dir: %d\n", ofdm->fft_plan.dir);
    printf("  mode: %d\n", ofdm->fft_plan.mode);
    print_cfr_t(&ofdm->tx_cfr);
    // Print DFT Plan for subframe
    printf("DFT Plan for Subframe:\n");
    for (int i = 0; i < 2; i++) {
        printf("  fft_plan_sf[%d] - init_size: %d, size: %d\n", i, ofdm->fft_plan_sf[i].init_size, ofdm->fft_plan_sf[i].size);
    }
  }

void print_sch_hl_cfg_nr(const srsran_sch_hl_cfg_nr_t* cfg) {
    if (!cfg) {
        printf("Null configuration pointer!\n");
        return;
    }
  
    // Print basic fields
    printf("scs_cfg: %u\n", cfg->scs_cfg);
    printf("Type A Position: %d\n", cfg->typeA_pos);
  
    printf("scrambling_id_present: %d\n", cfg->scrambling_id_present);
    printf("scrambling_id: %u\n", cfg->scambling_id);
    printf("mcs_table: %d\n", cfg->mcs_table);
    printf("dmrs_type: %d\n", cfg->dmrs_type);
    printf("dmrs_max_length: %d\n", cfg->dmrs_max_length);
  
    // Print DMRS Type A
    printf("DMRS Type A:\n");
    printf("  additional_pos: %d\n", cfg->dmrs_typeA.additional_pos);
    printf("  scrambling_id0_present: %d\n", cfg->dmrs_typeA.scrambling_id0_present);
    printf("  scrambling_id0: %u\n", cfg->dmrs_typeA.scrambling_id0);
    printf("  scrambling_id1_present: %d\n", cfg->dmrs_typeA.scrambling_id1_present);
    printf("  scrambling_id1: %u\n", cfg->dmrs_typeA.scrambling_id1);
    printf("  present: %d\n", cfg->dmrs_typeA.present);
  
    // Print DMRS Type B
    printf("DMRS Type B:\n");
    printf("  additional_pos: %d\n", cfg->dmrs_typeB.additional_pos);
    printf("  scrambling_id0_present: %d\n", cfg->dmrs_typeB.scrambling_id0_present);
    printf("  scrambling_id0: %u\n", cfg->dmrs_typeB.scrambling_id0);
    printf("  scrambling_id1_present: %d\n", cfg->dmrs_typeB.scrambling_id1_present);
    printf("  scrambling_id1: %u\n", cfg->dmrs_typeB.scrambling_id1);
    printf("  present: %d\n", cfg->dmrs_typeB.present);
  
    // Print common time RA
    printf("nof_common_time_ra: %u\n", cfg->nof_common_time_ra);
    for (uint32_t i = 0; i < cfg->nof_common_time_ra; i++) {
        printf("common_time_ra[%u] k: %d\n", i, cfg->common_time_ra[i].k);
        printf("common_time_ra[%u] mapping_type: %d\n", i, cfg->common_time_ra[i].mapping_type);
        printf("common_time_ra[%u] sliv: %d\n", i, cfg->common_time_ra[i].sliv);
    }
  
    // Print dedicated time RA
    printf("nof_dedicated_time_ra: %u\n", cfg->nof_dedicated_time_ra);
    for (uint32_t i = 0; i < cfg->nof_dedicated_time_ra; i++) {
      printf("dedicated_time_ra[%u] k: %d\n", i, cfg->dedicated_time_ra[i].k);
      printf("dedicated_time_ra[%u] mapping_type: %d\n", i, cfg->dedicated_time_ra[i].mapping_type);
      printf("dedicated_time_ra[%u] sliv: %d\n", i, cfg->dedicated_time_ra[i].sliv);
    }
  
    // Print RBG size configuration
    printf("rbg_size_cfg_1: %d\n", cfg->rbg_size_cfg_1);
  
    // Print allocation
    printf("Allocation (type): %d\n", cfg->alloc);
  
    // Print SCH configuration
    printf("SCH Config:\n");
    printf("  limited_buffer_rm: %u\n", cfg->sch_cfg.limited_buffer_rm);
    printf("  mcs_table: %d\n", cfg->sch_cfg.mcs_table);
    printf("  xoverhead: %d\n", cfg->sch_cfg.xoverhead);
  
    // Print CSI-RS ZP sets
    printf("PDSCH ZP CSI RS Set:\n");
    printf("  count: %u\n", cfg->p_zp_csi_rs_set.count);
  
    // Print Zero-Power CSI RS sets
    printf("PDSCH Zero-Power CSI RS Set:\n");
    printf("  count: %u\n", cfg->p_zp_csi_rs_set.count);
    for (uint32_t i = 0; i < cfg->p_zp_csi_rs_set.count; i++) {
      printf("  ZP CSI RS Resource[%u]:\n", i);
      printf("    id: %u\n", cfg->p_zp_csi_rs_set.data[i].id);
      // Print resource mapping
      printf("    resource_mapping:\n");
      printf("      row: %d\n", cfg->p_zp_csi_rs_set.data[i].resource_mapping.row);
      for (int j = 0; j < SRSRAN_CSI_RS_NOF_FREQ_DOMAIN_ALLOC_MAX; j++) {
        printf("      frequency_domain_alloc[%d]: %d\n", j, cfg->p_zp_csi_rs_set.data[i].resource_mapping.frequency_domain_alloc[j]);
      }
      printf("    nof_ports: %u\n", cfg->p_zp_csi_rs_set.data[i].resource_mapping.nof_ports);
      printf("    first_symbol_idx: %u\n", cfg->p_zp_csi_rs_set.data[i].resource_mapping.first_symbol_idx);
      printf("    first_symbol_idx2: %u\n", cfg->p_zp_csi_rs_set.data[i].resource_mapping.first_symbol_idx2);
      
      // Print CDM, density, and frequency band information
      printf("    cdm:\n");
      // Assuming srsran_csi_rs_cdm_t has fields (adjust if necessary)
      printf("      some_cdm_field: %d\n", cfg->p_zp_csi_rs_set.data[i].resource_mapping.cdm);
      
      printf("    density: %d\n", cfg->p_zp_csi_rs_set.data[i].resource_mapping.density);
      printf("    freq_band start_rb: %d\n", cfg->p_zp_csi_rs_set.data[i].resource_mapping.freq_band.start_rb);
      printf("    freq_band nof_rb: %d\n", cfg->p_zp_csi_rs_set.data[i].resource_mapping.freq_band.nof_rb);
  
      // Print periodicity
      printf("    periodicity:\n");
      printf("      period: %u\n", cfg->p_zp_csi_rs_set.data[i].periodicity.period);
      printf("      offset: %u\n", cfg->p_zp_csi_rs_set.data[i].periodicity.offset);
    }
    // Print NZP CSI-RS sets
    for (int i = 0; i < SRSRAN_PHCH_CFG_MAX_NOF_CSI_RS_SETS; i++) {
        printf("NZP CSI RS Set[%d]: count: %u\n", i, cfg->nzp_csi_rs_sets[i].count);
        printf("NZP CSI RS Set[%d]: trs_info: %u\n", i, cfg->nzp_csi_rs_sets[i].trs_info);
        
        // Print individual NZP CSI-RS resources
        for (uint32_t j = 0; j < cfg->nzp_csi_rs_sets[i].count; j++) {
            printf("  NZP CSI RS Resource[%d] id: %u\n", j, cfg->nzp_csi_rs_sets[i].data[j].id);
            printf("  NZP CSI RS Resource[%d] power_control_offset: %.2f\n", j, cfg->nzp_csi_rs_sets[i].data[j].power_control_offset);
            printf("  NZP CSI RS Resource[%d] power_control_offset_ss: %.2f\n", j, cfg->nzp_csi_rs_sets[i].data[j].power_control_offset_ss);
            printf("  NZP CSI RS Resource[%d] scrambling_id: %u\n", j, cfg->nzp_csi_rs_sets[i].data[j].scrambling_id);
            printf("  NZP CSI RS Resource[%d] periodicity period: %u\n", j, cfg->nzp_csi_rs_sets[i].data[j].periodicity.period);
            printf("  NZP CSI RS Resource[%d] periodicity offset: %u\n", j, cfg->nzp_csi_rs_sets[i].data[j].periodicity.offset);
  
        }
    }
  
    // Print transform precoder and scaling
    printf("enable_transform_precoder: %d\n", cfg->enable_transform_precoder);
    printf("scaling: %.2f\n", cfg->scaling);
  
    // Print beta offsets
    printf("beta_offsets.fix_ack: %.2f\n", cfg->beta_offsets.fix_ack);
    printf("beta_offsets.fix_csi1: %.2f\n", cfg->beta_offsets.fix_csi1);
    printf("beta_offsets.fix_csi2: %.2f\n", cfg->beta_offsets.fix_csi2);
  
    printf("beta_offsets.ack_index1: %.2u\n", cfg->beta_offsets.ack_index1);
    printf("beta_offsets.ack_index2: %.2u\n", cfg->beta_offsets.ack_index2);
    printf("beta_offsets.ack_index3: %.2u\n", cfg->beta_offsets.ack_index3);
  
    printf("beta_offsets.csi1_index1: %.2u\n", cfg->beta_offsets.csi1_index1);
    printf("beta_offsets.csi1_index2: %.2u\n", cfg->beta_offsets.csi1_index2);
    printf("beta_offsets.csi2_index1: %.2u\n", cfg->beta_offsets.csi2_index1);
    printf("beta_offsets.csi2_index2: %.2u\n", cfg->beta_offsets.csi2_index2);
  }
  
void print_srsran_sch_cfg_nr_t(srsran_sch_cfg_nr_t* cfg_nr) {
    printf("SCH Configuration for NR:\n");
    printf("  Scrambling ID Present: %d\n", cfg_nr->scrambling_id_present);
    printf("  Scrambling ID: %u\n", cfg_nr->scambling_id);
  
    print_srsran_dmrs_sch_cfg_t(&cfg_nr->dmrs);
    print_srsran_sch_grant_nr_t(&cfg_nr->grant);
    print_srsran_sch_cfg_t(&cfg_nr->sch_cfg);
    print_srsran_re_pattern_list_t(&cfg_nr->rvd_re);
  
    printf("  Uplink Control Information (PUSCH only):\n");
    printf("    Enable Transform Precoder: %d\n", cfg_nr->enable_transform_precoder);
    printf("    Frequency Hopping Enabled: %d\n", cfg_nr->freq_hopping_enabled);
  }
void print_srsran_dmrs_sch_cfg_t(srsran_dmrs_sch_cfg_t* dmrs) {
    printf("DMRS Configuration:\n");
    printf("  Type: %d\n", dmrs->type);
    printf("  Additional Position: %d\n", dmrs->additional_pos);
    printf("  Length: %d\n", dmrs->length);
    printf("  Scrambling ID 0 present: %d\n", dmrs->scrambling_id0_present);
    printf("  Scrambling ID 0: %u\n", dmrs->scrambling_id0);
    printf("  Scrambling ID 1 present: %d\n", dmrs->scrambling_id1_present);
    printf("  Scrambling ID 1: %u\n", dmrs->scrambling_id1);
    printf("  Type A Position: %d\n", dmrs->typeA_pos);
    printf("  LTE CRS to match around: %d\n", dmrs->lte_CRS_to_match_around);
    printf("  Reference Point K RB: %u\n", dmrs->reference_point_k_rb);
    printf("  Additional DMRS DL Alt: %d\n", dmrs->additional_DMRS_DL_Alt);
  }
void print_srsran_sch_grant_nr_t(srsran_sch_grant_nr_t* grant) {
    printf("SCH Grant:\n");
    printf("  RNTI: %u\n", grant->rnti);
    printf("  RNTI Type: %d\n", grant->rnti_type);
    printf("  Time Domain Resources:\n");
    printf("    k: %u\n", grant->k);
    printf("    S: %u\n", grant->S);
    printf("    L: %u\n", grant->L);
    printf("    Mapping: %d\n", grant->mapping);
    printf("  Frequency Domain Resources:\n");
    for (int i = 0; i < SRSRAN_MAX_PRB_NR; i++) {
        printf("    prb_idx[%d]: %d\n", i, grant->prb_idx[i]);
    }
    printf("  Number of PRBs: %u\n", grant->nof_prb);
    printf("  Number of DMRS CDM Groups Without Data: %u\n", grant->nof_dmrs_cdm_groups_without_data);
    printf("  Beta DMRS: %f\n", grant->beta_dmrs);
    printf("  Number of Layers: %u\n", grant->nof_layers);
    printf("  Scrambling SCID: %d\n", grant->n_scid);
    printf("  DCI Format: %d\n", grant->dci_format);
    printf("  DCI Search Space: %d\n", grant->dci_search_space);
    printf("  Transport Block Scaling Field: %u\n", grant->tb_scaling_field);
    // Print TB array (first element for brevity)
    printf("  TB[0] RV: %u\n", grant->tb[0].rv);
    printf("  TB[0] MCS: %u\n", grant->tb[0].mcs);
    printf("  TB[0] NDI: %u\n", grant->tb[0].ndi);
  }
void print_srsran_sch_cfg_t(srsran_sch_cfg_t* cfg) {
    printf("SCH Configuration:\n");
    printf("  MCS Table: %d\n", cfg->mcs_table);
    printf("  X Overhead: %d\n", cfg->xoverhead);
    printf("  Limited Buffer RM: %d\n", cfg->limited_buffer_rm);
  }
void print_srsran_re_pattern_list_t(srsran_re_pattern_list_t* pattern_list) {
    printf("Reserved RE Patterns:\n");
    printf("  Count: %u\n", pattern_list->count);
  
    for (uint32_t i = 0; i < pattern_list->count; i++) {
        srsran_re_pattern_t* pattern = &pattern_list->data[i]; // 获取每个模式
        
        // 打印 RB 范围和步长
        printf("  Pattern[%d]:\n", i);
        printf("    RB Begin: %u\n", pattern->rb_begin);
        printf("    RB End: %u\n", pattern->rb_end);
        printf("    RB Stride: %u\n", pattern->rb_stride);
  
        // 打印频域模式
        printf("    Frequency-domain pattern (sc):\n");
        for (int j = 0; j < SRSRAN_NRE; j++) {
            printf("      sc[%d]: %d\n", j, pattern->sc[j]);
        }
  
        // 打印符号模式
        printf("    Symbol pattern (symbol):\n");
        for (uint32_t j = 0; j < SRSRAN_NSYMB_PER_SLOT_NR; j++) {
            printf("      symbol[%d]: %d\n", j, pattern->symbol[j]);
        }
    }
  }
  void print_srsran_coreset(srsran_coreset_t coreset) {
    // 打印结构体中的每个字段
    printf("test yg print coreset_description: \n");
    printf("id=%u\n", coreset.id);
    printf("mapping_type=%s\n", 
        (coreset.mapping_type == srsran_coreset_mapping_type_non_interleaved) ? "NON_INTERLEAVED" : "INTERLEAVED");
    printf("duration=%u\n", coreset.duration);
    
    // 打印 freq_resources 数组
    printf("freq_resources=");
    for (int i = 0; i < SRSRAN_CORESET_FREQ_DOMAIN_RES_SIZE; i++) {
        printf("%d ", coreset.freq_resources[i]);
    }
    printf("\n");
    
    printf("dmrs_scrambling_id_present=%d\n", coreset.dmrs_scrambling_id_present);
    printf("dmrs_scrambling_id=%u\n", coreset.dmrs_scrambling_id);
    
    printf("precoder_granularity=%d\n", coreset.precoder_granularity);
    printf("interleaver_size=%d\n", coreset.interleaver_size);
    printf("reg_bundle_size=%d\n", coreset.reg_bundle_size);
    printf("shift_index=%u\n", coreset.shift_index);
    printf("offset_rb=%u\n\n", coreset.offset_rb);
  }
  void print_srsran_search_space(const srsran_search_space_t* ss)
  {
    if (!ss) {
      printf("  [SearchSpace] NULL\n");
      return;
    }
  
    printf("  SearchSpace:\n");
    printf("    id             : %u\n", ss->id);
    printf("    coreset_id     : %u\n", ss->coreset_id);
    printf("    duration       : %u\n", ss->duration);
    printf("    type           : %d\n", ss->type);
  
    printf("    DCI formats    : ");
    for (uint32_t i = 0; i < ss->nof_formats; i++) {
      printf("%d ", ss->formats[i]);
    }
    printf("\n");
  
    printf("    nof_candidates : ");
    for (uint32_t i = 0; i < SRSRAN_SEARCH_SPACE_NOF_AGGREGATION_LEVELS_NR; i++) {
      printf("%u ", ss->nof_candidates[i]);
    }
    printf("\n");
  }
  void print_srsran_pdcch_cfg_nr(const srsran_pdcch_cfg_nr_t* cfg)
{
  if (!cfg) {
    printf("[PDCCH CFG NR] NULL\n");
    return;
  }

  printf("==== PDCCH NR Configuration ====\n");

  /* ----------- 打印 CORESET ----------- */
  printf("-- CORESETs --\n");
  for (uint32_t i = 0; i < SRSRAN_UE_DL_NR_MAX_NOF_CORESET; i++) {
    if (cfg->coreset_present[i]) {
      printf("  CORESET[%u] present:\n", i);
      print_srsran_coreset(cfg->coreset[i]);
    } else {
      printf("  CORESET[%u] not present\n", i);
    }
  }

  /* ----------- 打印 SearchSpace ----------- */
  printf("-- SearchSpaces --\n");
  for (uint32_t i = 0; i < SRSRAN_UE_DL_NR_MAX_NOF_SEARCH_SPACE; i++) {
    if (cfg->search_space_present[i]) {
      printf("  SearchSpace[%u] present:\n", i);
      print_srsran_search_space(&cfg->search_space[i]);
    } else {
      printf("  SearchSpace[%u] not present\n", i);
    }
  }

  /* ----------- RA SearchSpace ----------- */
  printf("-- RA SearchSpace --\n");
  if (cfg->ra_search_space_present) {
    print_srsran_search_space(&cfg->ra_search_space);
  } else {
    printf("  RA SearchSpace not present\n");
  }

  printf("=================================\n");
}

void print_srsran_ue_ul_nr(srsran_ue_ul_nr_t ue_ul) {
    printf("max_prb=%d\n", ue_ul.max_prb);
    printf("freq_offset_hz=%f\n", ue_ul.freq_offset_hz);
    print_srsran_carrier_nr(&ue_ul.carrier);
    print_srsran_ofdm(&ue_ul.ifft);
}


void print_srsran_dci_cfg(const srsran_dci_cfg_t* cfg) {
    if (!cfg) {
        printf("cfg is NULL!\n");
        return;
    }
    printf("srsran_dci_cfg_t {\n");
    printf("  multiple_csi_request_enabled: %s\n", cfg->multiple_csi_request_enabled ? "true" : "false");
    printf("  cif_enabled:                  %s\n", cfg->cif_enabled ? "true" : "false");
    printf("  cif_present:                  %s\n", cfg->cif_present ? "true" : "false");
    printf("  srs_request_enabled:          %s\n", cfg->srs_request_enabled ? "true" : "false");
    printf("  ra_format_enabled:            %s\n", cfg->ra_format_enabled ? "true" : "false");
    printf("  is_not_ue_ss:                 %s\n", cfg->is_not_ue_ss ? "true" : "false");
    printf("}\n");
}

void print_srsran_dci_dl(const srsran_dci_dl_t* dci) {
    if (!dci) {
        printf("dci is NULL!\n");
        return;
    }

    printf("srsran_dci_dl_t {\n");
    printf("  rnti: %u\n", dci->rnti);
    printf("  format: %d\n", dci->format);
    printf("  location L: %d\n", dci->location.L);
    printf("  location ncce: %d\n", dci->location.ncce);

    printf("  ue_cc_idx: %u\n", dci->ue_cc_idx);

    printf("  alloc_type: %d\n", dci->alloc_type);

    // Codeword 信息
    /*for (int i = 0; i < SRSRAN_MAX_CODEWORDS; i++) {
        printf("  tb[%d]: %d\n", i, dci->tb[i]);
    }*/
    printf("  tb_cw_swap: %s\n", dci->tb_cw_swap ? "true" : "false");
    printf("  pinfo: %u\n", dci->pinfo);

    // Power control
    printf("  pconf: %s\n", dci->pconf ? "true" : "false");
    printf("  power_offset: %s\n", dci->power_offset ? "true" : "false");
    printf("  tpc_pucch: %u\n", dci->tpc_pucch);

    // PDCCH order
    printf("  is_pdcch_order: %s\n", dci->is_pdcch_order ? "true" : "false");
    printf("  preamble_idx: %u\n", dci->preamble_idx);
    printf("  prach_mask_idx: %u\n", dci->prach_mask_idx);

    // Release 10
    printf("  cif: %u\n", dci->cif);
    printf("  cif_present: %s\n", dci->cif_present ? "true" : "false");
    printf("  srs_request: %s\n", dci->srs_request ? "true" : "false");
    printf("  srs_request_present: %s\n", dci->srs_request_present ? "true" : "false");

    // Other params
    printf("  pid: %u\n", dci->pid);
    printf("  dai: %u\n", dci->dai);
    printf("  is_tdd: %s\n", dci->is_tdd ? "true" : "false");
    printf("  is_dwpts: %s\n", dci->is_dwpts ? "true" : "false");
    printf("  sram_id: %s\n", dci->sram_id ? "true" : "false");

#if SRSRAN_DCI_HEXDEBUG
    printf("  nof_bits: %u\n", dci->nof_bits);
    printf("  hex_str: %s\n", dci->hex_str);
#endif

    printf("}\n");
}


void print_srsran_ue_dl_nr(const srsran_ue_dl_nr_t* q)
{
    if (!q) {
        printf("srsran_ue_dl_nr_t: NULL pointer\n");
        return;
    }
    printf("=== srsran_ue_dl_nr_t ===\n");
    printf("max_prb: %u\n", q->max_prb);
    printf("nof_rx_antennas: %u\n", q->nof_rx_antennas);
    printf("pdcch_dmrs_corr_thr: %.3f\n", q->pdcch_dmrs_corr_thr);
    printf("pdcch_dmrs_epre_thr: %.3f\n", q->pdcch_dmrs_epre_thr);

    printf("\n--- Carrier ---\n");
    print_srsran_carrier_nr(&q->carrier);

    printf("\n--- PDCCH Config ---\n");
    print_srsran_pdcch_cfg_nr(&q->cfg);
    
    printf("\n--- PDCCH Blind Search Info ---\n");
    printf("pdcch_info_count: %u / %u\n",
           q->pdcch_info_count, SRSRAN_MAX_NOF_CANDIDATES_SLOT_NR);

    printf("\n--- DCI Messages ---\n");
    printf("dl_dci_msg_count: %u / %u\n", q->dl_dci_msg_count, SRSRAN_MAX_DCI_MSG_NR);
    printf("ul_dci_count: %u / %u\n", q->ul_dci_count, SRSRAN_MAX_DCI_MSG_NR);

    printf("=========================\n");
}
void print_hex(const uint8_t* data, size_t len) {
  for (size_t i = 0; i < len; ++i) {
      printf("%02x", data[i]);
  }
  printf("\n");
}
void print_packet_array_2format(const srsran::unique_byte_buffer_t& msg)
{
  uint32_t i;
  for (i = 0; i < msg->N_bytes; ++i) {
      printf("%02x ", msg->msg[i]);
  }
  printf("\n");
  for (i = 0; i < msg->N_bytes; ++i) {
      printf("%02x", msg->msg[i]);
  }
  printf("\n");
}
void hex_string_to_byte_array(const char *hex_string, uint8_t *byte_array) {
  size_t len = strlen(hex_string);
  for (size_t i = 0; i < len; i += 2) {
      sscanf(hex_string + i, "%2hhx", &byte_array[i / 2]);
  }
}