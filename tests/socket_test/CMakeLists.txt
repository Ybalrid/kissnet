add_executable(socket_test main.cpp ../../../kissnet.hpp)
find_package(Threads)
target_link_libraries(socket_test ${CMAKE_THREAD_LIBS_INIT})
