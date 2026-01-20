# srsRAN_4G
## for testing
```
mkdir build && cd build
cmake ../
make -j18
```


```./lib/examples/cell_search -b 1 -a type=x300,time_source=gpsdo -s 94 -e 104
./lib/examples/pdsch_ue -f 2120e6 -d -E 100
mkdir cache && mkdir cache/band_1 && mkdir cache/band_1/cell_420
cp ../output/* cache/band_1/cell_420/
./lib/test/common/gen_sample --type sib1_tac -c 420
./lib/test/common/gen_sample --type sib2_acbarring -c 420
./lib/test/common/gen_sample --type paging_sysinfmod -c 420
./lib/test/common/gen_sample --type paging_imsi -c 420 -m 460017837217696
./lib/examples/pdsch_enodeb -I UHD -x 1 -a type=x300,time_source=gpsdo -g 70 -c 420 --type sib1_tac
./lib/examples/pdsch_enodeb -I UHD -x 1 -a type=x300,time_source=gpsdo -g 70 -c 420 --type sib2_acbarring
./lib/examples/pdsch_enodeb -I UHD -x 1 -a type=x300,time_source=gpsdo -g 70 -c 420 --type paging_imsi
```
## for LTESniffer
```
cd LTESniffer
mkdir build && cd build
cmake .. -DENABLE_APPS=ON
make -j18
```
