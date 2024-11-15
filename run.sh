sudo apt update && sudo apt upgrade -y
sudo apt install libssl-dev libsodium-dev -y
sudo apt install astyle cmake gcc ninja-build libssl-dev python3-pytest python3-pytest-xdist unzip xsltproc doxygen graphviz python3-yaml valgrind -y
git clone -b main https://github.com/open-quantum-safe/liboqs.git
cd liboqs
mkdir build && cd build
cmake -DCMAKE_INSTALL_PREFIX=/usr/local -DOQS_USE_OPENSSL=ON ..
make -j$(nproc)
sudo make install
cd ..
cd ..
make