#include "srsran/phy/common/phy_common_nr.h"
#include "srsran/phy/dft/ofdm.h"
#include "srsran/phy/phch/pusch_nr.h"
#include "srsran/phy/ue/ue_ul_nr.h"
#include "srsran/phy/phch/dci.h"
#include "srsran/phy/phch/pdcch_cfg_nr.h"
#include "srsran/phy/ue/ue_dl_nr.h"
#include "srsran/common/byte_buffer.h"

void print_srsran_ue_ul_nr(srsran_ue_ul_nr_t ue_ul);

void print_srsran_carrier_nr(const srsran_carrier_nr_t* carrier);

void print_srsran_ofdm(const srsran_ofdm_t* ofdm);
void print_cfr_t(const srsran_cfr_t* cfr);
void print_cfr_tx_cfg(const srsran_cfr_cfg_t* cfr_tx_cfg);

void print_srsran_sch_cfg_nr_t(srsran_sch_cfg_nr_t* cfg_nr);
void print_srsran_sch_cfg_t(srsran_sch_cfg_t* cfg);
void print_srsran_sch_grant_nr_t(srsran_sch_grant_nr_t* grant);
void print_srsran_dmrs_sch_cfg_t(srsran_dmrs_sch_cfg_t* dmrs);
void print_srsran_re_pattern_list_t(srsran_re_pattern_list_t* pattern_list);

void print_sch_hl_cfg_nr(const srsran_sch_hl_cfg_nr_t* cfg);
void print_srsran_coreset(srsran_coreset_t coreset);
void print_srsran_dci_cfg(const srsran_dci_cfg_t* cfg);
void print_srsran_dci_dl(const srsran_dci_dl_t* dci);
void print_srsran_coreset(srsran_coreset_t coreset);

void print_srsran_pdcch_cfg_nr(const srsran_pdcch_cfg_nr_t* cfg);
void print_srsran_ue_dl_nr(const srsran_ue_dl_nr_t* q);
void print_hex(const uint8_t* data, size_t len);
void print_packet_array_2format(const srsran::unique_byte_buffer_t& msg);
void hex_string_to_byte_array(const char *hex_string, uint8_t *byte_array);

