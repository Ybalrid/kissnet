CMAKE_MINIMUM_REQUIRED(VERSION 3.1)

set(CMAKE_CXX_STANDARD 17)

project(kissnet)

include_directories (.)

add_library(kissnet STATIC ./kissnet.cpp)
