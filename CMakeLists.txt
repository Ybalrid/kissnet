CMAKE_MINIMUM_REQUIRED(VERSION 3.13)
project(kissnet_ci LANGUAGES CXX)

option(build_tests "build test programs")

find_package(OpenSSL REQUIRED)

set(incdir ${CMAKE_CURRENT_SOURCE_DIR})

add_executable(output kissnet.cpp)
target_include_directories(output PRIVATE ${incdir})
target_link_libraries(output PRIVATE OpenSSL::SSL OpenSSL::Crypto)
target_compile_features(output PRIVATE cxx_std_17)

if(build_tests)
  add_subdirectory(examples)
  add_subdirectory(tests)
endif()

include(FeatureSummary)
add_feature_info(Tests build_tests "kissnet examples and tests")
feature_summary(WHAT ALL)
