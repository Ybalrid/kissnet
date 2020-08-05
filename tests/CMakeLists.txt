IF(MSVC)
  # Force to always compile with W4
  IF(CMAKE_CXX_FLAGS MATCHES "/W[0-4]")
    STRING(REGEX REPLACE "/W[0-4]" "/W4" CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS}")
  ELSE()
    string(APPEND CMAKE_CXX_FLAGS " /W4")
  ENDIF()
ELSEIF(CMAKE_COMPILER_IS_GNUCC OR CMAKE_COMPILER_IS_GNUCXX)
  # Update if necessary
  string(APPEND CMAKE_CXX_FLAGS " -Wall -Wno-long-long -pedantic")
ENDIF()

foreach(d acceptor endpoint error_handler simple socket)
  add_subdirectory(${d})
endforeach()

set(WINSOCK_LIBRARIES)
if(WIN32)
set(WINSOCK_LIBRARIES wsock32 ws2_32 Iphlpapi)
endif()

foreach(t acceptor_test endpoint_test error_handler_test simple_test socket_test)
  target_compile_features(${t} PRIVATE cxx_std_17)
  target_include_directories(${t} PRIVATE ${incdir})
  set_target_properties(${t} PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR})
  target_link_libraries(${t} PRIVATE ${WINSOCK_LIBRARIES})
endforeach()
