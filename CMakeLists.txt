cmake_minimum_required(VERSION 3.16)
project(dcon LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)

add_executable(dcon dcon.cpp)
target_link_libraries(dcon OpenSSL::Crypto Threads::Threads)
