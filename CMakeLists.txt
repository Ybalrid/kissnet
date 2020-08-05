CMAKE_MINIMUM_REQUIRED(VERSION 3.8)
project(kissnet_ci LANGUAGES CXX)

include_directories(${CMAKE_CURRENT_SOURCE_DIR})

find_package(OpenSSL REQUIRED)

add_executable(output kissnet.cpp)

target_link_libraries(output PRIVATE OpenSSL::SSL OpenSSL::Crypto)
target_compile_features(output PRIVATE cxx_std_17)
