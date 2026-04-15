#include "srsran/mac/mac_rar_pdu_nr.h"

  srsran::mac_rar_pdu_nr rar_pdu;
  if (!rar_pdu.unpack(data->msg, data->N_bytes)) {
    logger.error("Error decoding RACH msg2");
    return false;
  }