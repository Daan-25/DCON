cmake_minimum_required(VERSION 3.16)
project(dcon_wallet LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_AUTOUIC ON)

find_package(Qt6 REQUIRED COMPONENTS Widgets)

add_executable(dcon-wallet
  src/main.cpp
  src/MainWindow.cpp
)

target_include_directories(dcon-wallet PRIVATE src)

target_link_libraries(dcon-wallet Qt6::Widgets)
