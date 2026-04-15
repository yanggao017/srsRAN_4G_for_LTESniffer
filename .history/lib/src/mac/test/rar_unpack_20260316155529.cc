#include "srsran/mac/mac_rar_pdu_nr.h"
//const char* mac_hex = "01a000000800103a2800000000";
const char* mac_hex = "01A000000800183A281800000000";
void hex_string_to_byte_array(const char *hex_string, uint8_t *byte_array) {
  size_t len = strlen(hex_string);
  for (size_t i = 0; i < len; i += 2) {
      sscanf(hex_string + i, "%2hhx", &byte_array[i / 2]);
  }
}

int main(int argc, char** argv)
{
  srsran::mac_rar_pdu_nr rar_pdu;
  if (!rar_pdu.unpack(data->msg, data->N_bytes)) {
    logger.error("Error decoding RACH msg2");
    return false;
  }

  return 0;
}