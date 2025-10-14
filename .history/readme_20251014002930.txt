可以注入（sigover）、搜索常见FDD 9个band的小区 以及嗅探指定频率小区的SIB1、SIB2、MIB，并保存十六进制和hex内容、cell配置
./lib/test/common/gen_sample -v -t 3 -r 0xffff -s 5 -o output_sib1_tac -p 100 -c 420
sudo ./lib/examples/pdsch_enodeb -f 2120e6 -I UHD -x 1 -a type=x300,time_source=gpsdo -g 70 -i output_sib1_tac
./lib/examples/cell_search -a type=x300,time_source=gpsdo
./lib/examples/pdsch_ue -f 2120e6 -d