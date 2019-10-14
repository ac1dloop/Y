cmake_minimum_required(VERSION 2.8)

project(socket)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_INCLUDE_CURRENT_DIR ON)

find_package(Threads REQUIRED)

add_executable(udp_srv "udp_srv.cpp")
add_executable(udp_cli "udp_cli.cpp")
target_link_libraries(udp_cli ${CMAKE_THREAD_LIBS_INIT})

add_executable(un_udp_srv "un_udp_srv.cpp")
add_executable(un_udp_cli "un_udp_cli.cpp")
target_link_libraries(un_udp_cli ${CMAKE_THREAD_LIBS_INIT})

add_executable(tcp_srv "tcp_srv.cpp")
target_link_libraries(tcp_srv ${CMAKE_THREAD_LIBS_INIT})

add_executable(resolver "resolver.cpp")

#add_executable(unix_udp_srv "examples/unix_udp_srv.cpp")
#target_link_libraries(unix_udp_srv ${CMAKE_THREAD_LIBS_INIT})

#add_executable(unix_udp_cli "examples/unix_udp_cli.cpp")
#target_link_libraries(unix_udp_cli ${CMAKE_THREAD_LIBS_INIT})

#add_executable(rule5 "tests/check_rule5.cpp")
#enable_testing()

#add_test(CheckRuleOfFive rule5)
