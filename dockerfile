FROM ubuntu:20.04

# 设置环境变量，避免交互式安装
ENV DEBIAN_FRONTEND=noninteractive

RUN sed -i 's/archive.ubuntu.com/mirrors.ustc.edu.cn/g' /etc/apt/sources.list \
    && sed -i 's/security.ubuntu.com/mirrors.ustc.edu.cn/g' /etc/apt/sources.list \
	&& apt update --no-install-recommends

RUN apt-get -y install autoconf automake build-essential ccache cmake cpufrequtils doxygen ethtool fort77 g++ gir1.2-gtk-3.0 git gobject-introspection gpsd gpsd-clients inetutils-tools libasound2-dev libboost-all-dev libcomedi-dev libcppunit-dev libfftw3-bin libfftw3-dev libfftw3-doc libfontconfig1-dev libgmp-dev libgps-dev libgsl-dev liblog4cpp5-dev libncurses5 libncurses5-dev libpulse-dev libqt5opengl5-dev libqwt-qt5-dev libsdl1.2-dev libtool libudev-dev libusb-1.0-0 libusb-1.0-0-dev libusb-dev libxi-dev libxrender-dev libzmq3-dev libzmq5 ncurses-bin python3-cheetah python3-click python3-click-plugins python3-click-threading python3-dev python3-docutils python3-gi python3-gi-cairo python3-gps python3-lxml python3-mako python3-numpy python3-numpy-dbg python3-opengl python3-pyqt5 python3-requests python3-scipy python3-setuptools python3-six python3-sphinx python3-yaml python3-zmq python3-ruamel.yaml swig wget

RUN apt-get install -y software-properties-common ca-certificates curl gnupg \
    && add-apt-repository ppa:ettusresearch/uhd

RUN apt-get install -y libuhd-dev uhd-host


# 创建工作目录
WORKDIR /workspace

# 复制项目文件
COPY . .

RUN apt-get install -y libmbedtls-dev libconfig-dev libsctp-dev libconfig++-dev

# 创建构建目录并编译
RUN mkdir -p build && cd build \
    && cmake .. -DENABLE_AVX2=OFF -DENABLE_AVX2_16BIT=OFF -DENABLE_SSE=ON \
    && make -j$(nproc) \
    && cp ../Input_Signal/420/* .

# 设置 UHD 设备规则
RUN echo 'SUBSYSTEM=="usb", ATTR{idVendor}=="2500", MODE="0666"' > /etc/udev/rules.d/90-usrp.rules

# 初始化 UHD 镜像
RUN uhd_images_downloader

# 设置环境变量
ENV LD_LIBRARY_PATH=/usr/local/lib:$LD_LIBRARY_PATH
ENV PATH=/usr/local/bin:$PATH

WORKDIR /workspace/build
CMD ["/bin/bash"]