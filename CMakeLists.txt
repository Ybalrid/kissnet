CMAKE_MINIMUM_REQUIRED(CMAKE_VERSION 3.1)

set(CMAKE_CXX_STANDARD 17)

project(kissnet_ci)

include_directories (.)

add_executable(output ./kissnet.cpp)
