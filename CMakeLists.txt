cmake_minimum_required(VERSION 2.8)

project(socket)

set(CMAKE_CXX_FLAGS "-pthread -std=c++11")

add_executable(${PROJECT_NAME} "main.cpp" "socket.h")

add_executable("client_test" "client.cpp")
add_executable("echo_server" "server.cpp")
add_executable("udpsrv" "udpsrv.cpp")
