cmake_minimum_required(VERSION 3.17)

project(ibmi_bruteforce LANGUAGES CXX)

add_executable(ibmbrute
    src/main.cpp
    src/dst_hash.cpp
)

target_compile_features(ibmbrute PRIVATE cxx_std_17)

if (MSVC)
    target_compile_options(ibmbrute PRIVATE
        $<$<COMPILE_LANGUAGE:CXX,OBJCXX>:/W4>
        $<$<COMPILE_LANGUAGE:CXX,OBJCXX>:/permissive->
    )
else()
    target_compile_options(ibmbrute PRIVATE
        $<$<COMPILE_LANGUAGE:CXX,OBJCXX>:-Wall>
        $<$<COMPILE_LANGUAGE:CXX,OBJCXX>:-Wextra>
        $<$<COMPILE_LANGUAGE:CXX,OBJCXX>:-Wpedantic>
    )
endif()

set(IBMBRUTE_HAVE_METAL_VALUE 0)
set(IBMBRUTE_HAVE_CUDA_VALUE 0)
set(IBMBRUTE_CUDA_STATUS "disabled")

include(CheckLanguage)

find_package(CUDAToolkit QUIET)
if (CUDAToolkit_FOUND)
    check_language(CUDA)
    if (CMAKE_CUDA_COMPILER)
        enable_language(CUDA)
        target_sources(ibmbrute PRIVATE src/cuda/cuda_backend.cu)
        target_link_libraries(ibmbrute PRIVATE CUDA::cudart)
        set_target_properties(ibmbrute PROPERTIES
            CUDA_STANDARD 17
            CUDA_STANDARD_REQUIRED ON
        )
        set(IBMBRUTE_HAVE_CUDA_VALUE 1)
        set(IBMBRUTE_CUDA_STATUS "enabled (version ${CUDAToolkit_VERSION})")
    else()
        set(IBMBRUTE_CUDA_STATUS "toolkit found, but no CUDA compiler is available")
    endif()
endif()

if (APPLE)
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
target_compile_definitions(ibmbrute PRIVATE IBMBRUTE_HAVE_CUDA=${IBMBRUTE_HAVE_CUDA_VALUE})

message(STATUS "CUDA toolkit support: ${IBMBRUTE_CUDA_STATUS}")

enable_testing()
add_test(NAME ibmbrute_verify COMMAND ibmbrute --verify)
