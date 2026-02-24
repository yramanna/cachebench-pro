#!/usr/bin/env bash
echo "==> Installing build tools (meson, ninja, pkg-config, pip)..."
sudo apt install -y meson ninja-build pkg-config python3-pip

echo "==> Installing pyelftools..."
pip install pyelftools

echo "==> Updating apt and installing RDMA/DPDK dependencies..."
sudo apt-get update
sudo apt-get install -y \
  rdma-core ibverbs-providers \
  libibverbs-dev librdmacm-dev libmlx5-1 \
  pkg-config libnuma-dev

echo "==> Installing DPDK build dependencies..."
sudo apt-get install -y \
  build-essential libnuma-dev libelf-dev \
  python3-pip pkg-config meson ninja-build

echo "==> Cloning and building DPDK v21.11..."
git clone https://dpdk.org/git/dpdk
cd dpdk
git checkout v21.11
meson -Ddisable_drivers=common/octeontx,common/octeontx2 build
ninja -C build
sudo ninja -C build install
sudo ldconfig
cd ~

echo "==> Cloning and building dnetperf..."
git clone git@github.com:aagontuk/dnetperf.git
cd dnetperf
export PKG_CONFIG_PATH=$PKG_CONFIG_PATH:/usr/local/lib/x86_64-linux-gnu/pkgconfig/
git checkout base
make -C client
make -C server
sudo sysctl -w vm.nr_hugepages=1024
cd ~

echo "==> Cloning and building smartkv/dmemslap..."
git clone git@github.com:utah-scs/smartkv.git
cd smartkv/dmemslap
make
cd ~

echo "==> All done."
