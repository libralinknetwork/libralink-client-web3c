# Work in Progress

`Note: This repository needs to be adapted for embedded development`

[![CircleCI](https://dl.circleci.com/status-badge/img/circleci/3mRSbP89jqQQqkK78hQhCE/7SrKkwegk1nYgExDNTEK3H/tree/main.svg?style=svg)](https://dl.circleci.com/status-badge/redirect/circleci/3mRSbP89jqQQqkK78hQhCE/7SrKkwegk1nYgExDNTEK3H/tree/main)

## Dev Environment Setup
```
brew install cmake
brew install autoconf automake libtool pkg-config
```

## Clone and Build libsecp256k1
```
git clone https://github.com/bitcoin-core/secp256k1.git
cd secp256k1
./autogen.sh
./configure --enable-module-recovery
make
sudo make install
```

## Build Project
```
mkdir build
cd build
cmake ..
make
./libralink-client-web3c
```