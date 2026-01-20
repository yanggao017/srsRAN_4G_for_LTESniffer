FROM ubuntu:22.04

# ---- 基础设置 ----
ENV DEBIAN_FRONTEND=noninteractive
ENV LC_ALL=C.UTF-8
ENV LANG=C.UTF-8

# ---- 使用 USTC 镜像 ----
RUN sed -i 's/archive.ubuntu.com/mirrors.ustc.edu.cn/g' /etc/apt/sources.list \
    && sed -i 's/security.ubuntu.com/mirrors.ustc.edu.cn/g' /etc/apt/sources.list

# ---- 安装依赖 ----
RUN apt-get update --fix-missing && apt-get install -y --no-install-recommends \
    software-properties-common ca-certificates curl gnupg wget lsb-release apt-transport-https \
    autoconf automake build-essential ccache cmake cpufrequtils doxygen ethtool fort77 g++ \
    git gobject-introspection gpsd gpsd-clients inetutils-tools libasound2-dev \
    libboost-all-dev libcomedi-dev libcppunit-dev libfftw3-bin libfftw3-dev libfftw3-doc \
    libfontconfig1-dev libgmp-dev libgps-dev libgsl-dev liblog4cpp5-dev libncurses5 \
    libncurses5-dev libpulse-dev libqt5opengl5-dev libqwt-qt5-dev libsdl1.2-dev \
    libtool libudev-dev libusb-1.0-0 libusb-1.0-0-dev libxi-dev libxrender-dev \
    libzmq3-dev python3-dev python3-docutils python3-gi python3-gi-cairo python3-gps \
    python3-lxml python3-mako python3-numpy python3-opengl python3-pyqt5 python3-requests \
    python3-scipy python3-setuptools python3-six python3-sphinx python3-yaml python3-zmq \
    python3-ruamel.yaml swig iproute2 net-tools iputils-ping ethtool \
    libmbedtls-dev libconfig-dev libsctp-dev libconfig++-dev libboost-program-options-dev \
    libglib2.0-dev libcurl4-openssl-dev qtdeclarative5-dev libqt5charts5-dev --fix-missing

# ---- UHD ----
RUN add-apt-repository -y ppa:ettusresearch/uhd \
    && apt-get update --fix-missing \
    && apt-get install -y libuhd-dev uhd-host \
    && uhd_images_downloader

# ---- UHD 设备规则 ----
RUN echo 'SUBSYSTEM=="usb", ATTR{idVendor}=="2500", MODE="0666"' > /etc/udev/rules.d/90-usrp.rules

# ---- 环境变量 ----
ENV UHD_IMAGES_DIR=/usr/share/uhd/images
ENV LD_LIBRARY_PATH=/usr/local/lib
ENV PATH=/usr/local/bin:$PATH

# ---- 工作目录 ----
WORKDIR /home/workspace/build

# ---- 默认启动 ----
CMD ["/bin/bash"]