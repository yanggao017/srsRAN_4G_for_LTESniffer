#include "srsran/mac/mac_rar_pdu_nr.h"
const char* mac_hex = "8062001807f72619a4";
void hex_string_to_byte_array(const char *hex_string, uint8_t *byte_array) {
  size_t len = strlen(hex_string);
  for (size_t i = 0; i < len; i += 2) {
      sscanf(hex_string + i, "%2hhx", &byte_array[i / 2]);
  }
}

int main(int argc, char** argv)
{
  srsran::mac_rar_pdu_nr rar_pdu;
  size_t mac_len = strlen(mac_hex) / 2;
  uint8_t data[mac_len];
  hex_string_to_byte_array(mac_hex, data);

  if (!rar_pdu.unpack(data, mac_len)) {
    printf("Error decoding RACH msg2");
    return -1;
  }
  uint32_t num_subpdus = rar_pdu.get_num_subpdus();
  if (num_subpdus == 0) {
    printf("No subpdus in RAR");
    return -1;
  }
  printf("Number of subpdus: %u\n", num_subpdus);
  for (uint32_t i = 0; i < num_subpdus; i++) {
    const srsran::mac_rar_subpdu_nr& subpdu = rar_pdu.get_subpdu(i);
    printf("SubPDU %u: has_rapid=%u, has_backoff=%u, temp_crnti=0x%04x, ta=%u, rapid=%u\n",
           i, subpdu.has_rapid(), subpdu.has_backoff(), subpdu.get_temp_crnti(),
           subpdu.get_ta(), subpdu.get_rapid());
  }
      // 打开 PCAP 文件
    pcap_handle = std::unique_ptr<mac_pcap>(new mac_pcap());
    pcap_handle->open("output_mac_pdu.pcap");

    // 写入
    if (write_mac_pdu(generation, direction, type, mac_hex)) {
        std::cerr << "写入 MAC PDU 失败！\n";
        return SRSRAN_ERROR;
    }

    // 关闭
    pcap_handle->close();
    std::cout << "写入完成，输出文件：output_mac_pdu.pcap\n";

  

  return 0;
}