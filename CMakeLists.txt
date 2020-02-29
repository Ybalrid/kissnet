CMAKE_MINIMUM_REQUIRED(VERSION 3.1)

set(CMAKE_CXX_STANDARD 17)

project(kissnet_ci)

include_directories (.)

find_package(OpenSSL REQUIRED)

add_executable(output ./kissnet.cpp)

target_link_libraries(output PRIVATE OpenSSL::SSL OpenSSL::Crypto)
