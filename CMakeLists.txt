cmake_minimum_required(VERSION 2.8)

project(socket)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_INCLUDE_CURRENT_DIR ON)

find_package(Threads REQUIRED)

add_executable(tcp_srv "examples/tcp_srv.cpp")
target_link_libraries(tcp_srv ${CMAKE_THREAD_LIBS_INIT})

add_executable(tcp_select "examples/tcp_select.cpp")

add_executable(udp_cli "examples/udp_cli.cpp")
add_executable(udp_srv "examples/udp_srv.cpp")

add_executable(rule5 "tests/check_rule5.cpp")

#enable_testing()

add_test(CheckRuleOfFive rule5)
