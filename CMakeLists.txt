cmake_minimum_required(VERSION 3.28)
project(sistemasDisquetos C)

link_libraries(crypto)
set(CMAKE_C_STANDARD 99)

add_executable(sistemasDisquetos main.c)
