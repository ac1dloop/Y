cmake_minimum_required(VERSION 2.8)

project(socket)

set(CMAKE_CXX_FLAGS "-pthread -std=c++11")

add_executable(${PROJECT_NAME} "main.cpp" "socket.h")

add_executable("client_test" "examples/client.cpp")
add_executable("echo_server" "examples/server.cpp")
add_executable("udpsrv" "examples/udpsrv.cpp")
add_executable("udpcli" "examples/udpcli.cpp")
add_executable("srv_custom" "examples/telnet.cpp")
