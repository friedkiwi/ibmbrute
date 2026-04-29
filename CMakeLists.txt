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

set(IBMBRUTE_HAVE_METAL_VALUE 0)

if (APPLE)
    include(CheckLanguage)
    check_language(OBJCXX)
    if (CMAKE_OBJCXX_COMPILER)
        find_library(IBMBRUTE_METAL_FRAMEWORK Metal)
        find_library(IBMBRUTE_FOUNDATION_FRAMEWORK Foundation)
        find_library(IBMBRUTE_COREGRAPHICS_FRAMEWORK CoreGraphics)
        if (IBMBRUTE_METAL_FRAMEWORK AND IBMBRUTE_FOUNDATION_FRAMEWORK AND IBMBRUTE_COREGRAPHICS_FRAMEWORK)
            enable_language(OBJCXX)
            target_sources(ibmbrute PRIVATE src/metal/metal_backend.mm)
            set(IBMBRUTE_HAVE_METAL_VALUE 1)
            target_link_libraries(ibmbrute PRIVATE
                ${IBMBRUTE_METAL_FRAMEWORK}
                ${IBMBRUTE_FOUNDATION_FRAMEWORK}
                ${IBMBRUTE_COREGRAPHICS_FRAMEWORK}
            )
        endif()
    endif()
endif()

target_compile_definitions(ibmbrute PRIVATE IBMBRUTE_HAVE_METAL=${IBMBRUTE_HAVE_METAL_VALUE})

enable_testing()
add_test(NAME ibmbrute_verify COMMAND ibmbrute --verify)
