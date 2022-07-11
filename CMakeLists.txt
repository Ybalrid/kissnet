CMAKE_MINIMUM_REQUIRED(VERSION 3.13)
set(CMAKE_CONFIGURATION_TYPES "Release;RelWithDebInfo;Debug" CACHE STRING "Build type selections" FORCE)
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE RelWithDebInfo CACHE STRING "default build type")
endif()
project(kissnet_ci
  LANGUAGES CXX
  DESCRIPTION "header-only C++ network interface"
  HOMEPAGE_URL https://github.com/Ybalrid/kissnet
  VERSION 0.1.0)
enable_testing()

option(kissnet_BUILD_TESTING "build test programs")

set(CMAKE_EXPORT_COMPILE_COMMANDS on)

set(CI $ENV{CI})  # we'll use this to omit CI-shaky tests

add_library(kissnet SHARED kissnet.cpp)
add_library(kissnet::kissnet ALIAS kissnet)
target_compile_features(kissnet INTERFACE cxx_std_17)
target_include_directories(kissnet INTERFACE
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>)
set_property(TARGET kissnet PROPERTY POSITION_INDEPENDENT_CODE ON)

find_package(OpenSSL)

if(OpenSSL_FOUND)
  target_link_libraries(kissnet PRIVATE OpenSSL::SSL OpenSSL::Crypto)
  target_compile_definitions(kissnet PRIVATE KISSNET_USE_OPENSSL)
endif()

if(kissnet_BUILD_TESTING)
  add_subdirectory(examples)
  add_subdirectory(tests)
endif()

include(GNUInstallDirs)

install(TARGETS kissnet
  EXPORT kissnetTargets
  DESTINATION .)

install(EXPORT kissnetTargets
  NAMESPACE kissnet::
  DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/kissnet)

install(FILES kissnet.hpp
  DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

include(FeatureSummary)
add_feature_info(Tests kissnet_BUILD_TESTING "kissnet examples and tests")
feature_summary(WHAT ALL)
