
## Fixed_sigover_injector

### Fixed some issues 

1. Fixed the Errors that may occur during the CMake and Make processes.

2. Fixed the SIB2-AcBarringInfo(Change the inject subframe from subframe 1 to subframe 0)

### TODO ISSUES

1. The version of SRSLTE in the original project was too old and lacked the CFO automatic compensation function, which led to problems in synchronization and MIB decoding

### Usage

```bash
mkdir build && cd build

cmake .. -DENABLE_AVX2=OFF -DENABLE_AVX2_16BIT=OFF -DENABLE_SSE=ON

make -j $(nproc)
```