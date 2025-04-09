cmake_minimum_required(VERSION 3.10)
project(libralink-client-web3c C)

set(CMAKE_C_STANDARD 11)

add_executable(libralink-client-web3c main.c keccak/keccak.c)
find_library(SECP256K1_LIB secp256k1)
target_link_libraries(libralink-client-web3c ${SECP256K1_LIB})
