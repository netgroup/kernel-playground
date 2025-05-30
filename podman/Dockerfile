# Use the Ubuntu 24.04 base image
FROM ubuntu:24.04

# Replace sources.list with the specified mirror
RUN sed -i 's|http://archive.ubuntu.com/ubuntu/|http://ubuntu.mirror.garr.it/ubuntu/|g' \
	/etc/apt/sources.list.d/ubuntu.sources

# Update package lists
RUN apt-get clean && apt-get update

# Set environment variables to avoid prompts during build
ENV DEBIAN_FRONTEND=noninteractive

# Install any packages or dependencies here
RUN apt-get install -y \
	tmux \
	curl \
	wget \
	lsb-release \
	software-properties-common \
	pkg-config \
	binutils-dev \
	libcap-dev \
	libelf-dev \
	gcc-multilib \
	gpg \
	vim \
	universal-ctags \
	git \
	g++ \
	cmake \
	libssl-dev \
	libcurl4-openssl-dev \
	libcap-ng-dev \
	systemd \
	init \
	iproute2 \
	iputils-ping \
	tcpdump \
	net-tools \
	fakeroot \
	build-essential \
	ncurses-dev \
	xz-utils \
	bc \
	flex \
	bison \
	pahole \
	qemu-system-x86 \
	debootstrap

# install latest llvm for ebpf
RUN mkdir -p /opt/llvm && cd /opt/llvm && \
	wget https://apt.llvm.org/llvm.sh && \
	chmod +x llvm.sh && \
	./llvm.sh all && \
	wget https://raw.githubusercontent.com/ShangjinTang/dotfiles/05ef87daae29475244c276db5d406b58c52be445/linux/ubuntu/22.04/bin/update-alternatives-clang && \
	chmod +x update-alternatives-clang && \
	sed -i 's/sudo//g' update-alternatives-clang && \
	./update-alternatives-clang

# update cache for dynamic libraries
RUN ldconfig

# Cleanup package cache to reduce image size
RUN apt-get clean

#ENTRYPOINT ["/sbin/init"]
CMD ["/sbin/init"]
