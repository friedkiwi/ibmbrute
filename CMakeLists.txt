cmake_minimum_required(VERSION 3.16)

project(ibmi_bruteforce LANGUAGES CXX)

add_executable(ibmbrute
    src/main.cpp
    src/dst_hash.cpp
)

target_compile_features(ibmbrute PRIVATE cxx_std_17)

if (MSVC)
    target_compile_options(ibmbrute PRIVATE /W4 /permissive-)
else()
    target_compile_options(ibmbrute PRIVATE -Wall -Wextra -Wpedantic)
endif()

enable_testing()
add_test(NAME ibmbrute_verify COMMAND ibmbrute --verify)
