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

option(build_tests "build test programs" ON)

# this helps linters e.g. Visual Studio Intellicode work properly
set(CMAKE_EXPORT_COMPILE_COMMANDS on)

find_package(OpenSSL)

set(incdir ${CMAKE_CURRENT_SOURCE_DIR})

add_executable(output kissnet.cpp)
target_include_directories(output PRIVATE ${incdir})
target_compile_features(output PRIVATE cxx_std_17)
add_test(NAME HasOpenSSL COMMAND $<TARGET_FILE:output>)
if(OpenSSL_FOUND)
  target_link_libraries(output PRIVATE OpenSSL::SSL OpenSSL::Crypto)
  target_compile_definitions(output PRIVATE KISSNET_USE_OPENSSL)
endif()

if(build_tests)
  add_subdirectory(examples)
  add_subdirectory(tests)
endif()

include(FeatureSummary)
add_feature_info(Tests build_tests "kissnet examples and tests")
feature_summary(WHAT ALL)
