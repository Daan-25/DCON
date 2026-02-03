cmake_minimum_required(VERSION 3.16)
project(dcon LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)

add_executable(dcon
  src/base58.cpp
  src/block.cpp
  src/blockchain.cpp
  src/crypto.cpp
  src/main.cpp
  src/net.cpp
  src/node.cpp
  src/pow.cpp
  src/serialize.cpp
  src/storage.cpp
  src/transaction.cpp
  src/wallet.cpp
)

target_include_directories(dcon PRIVATE include)
target_link_libraries(dcon OpenSSL::Crypto Threads::Threads)
