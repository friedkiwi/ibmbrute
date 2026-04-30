cmake_minimum_required(VERSION 3.17)

project(ibmi_bruteforce LANGUAGES CXX)

set(IBMBRUTE_COMMON_SOURCES
    src/dst_hash.cpp
    src/app/app_util.cpp
    src/app/session.cpp
    src/app/cracker.cpp
    src/app/run.cpp
)

add_executable(ibmbrute
    src/main.cpp
    ${IBMBRUTE_COMMON_SOURCES}
)

set(IBMBRUTE_HAVE_METAL_VALUE 0)
set(IBMBRUTE_HAVE_CUDA_VALUE 0)
set(IBMBRUTE_CUDA_STATUS "disabled")
set(IBMBRUTE_CUDA_SOURCES)

include(CheckLanguage)

find_package(CUDAToolkit QUIET)
if (CUDAToolkit_FOUND)
    check_language(CUDA)
    if (CMAKE_CUDA_COMPILER)
        enable_language(CUDA)
        file(MAKE_DIRECTORY "${CMAKE_BINARY_DIR}/cmake")
        file(WRITE "${CMAKE_BINARY_DIR}/cmake/cuda_cxx17_probe.cu" [[
#include <cuda_runtime.h>
#include <functional>

__global__ void probe_kernel() {}

int probe()
{
    std::function<int()> fn = [] { return 0; };
    return fn();
}
]])
        set(IBMBRUTE_PREVIOUS_TRY_COMPILE_TARGET_TYPE "${CMAKE_TRY_COMPILE_TARGET_TYPE}")
        set(CMAKE_TRY_COMPILE_TARGET_TYPE STATIC_LIBRARY)
        try_compile(IBMBRUTE_CUDA_CXX17_WORKS
            "${CMAKE_BINARY_DIR}/cmake/cuda_cxx17_probe"
            "${CMAKE_BINARY_DIR}/cmake/cuda_cxx17_probe.cu"
            CMAKE_FLAGS
                "-DCMAKE_CUDA_STANDARD=17"
                "-DCMAKE_CUDA_STANDARD_REQUIRED=ON"
            OUTPUT_VARIABLE IBMBRUTE_CUDA_CXX17_OUTPUT
        )
        set(CMAKE_TRY_COMPILE_TARGET_TYPE "${IBMBRUTE_PREVIOUS_TRY_COMPILE_TARGET_TYPE}")

        if (IBMBRUTE_CUDA_CXX17_WORKS)
            target_sources(ibmbrute PRIVATE src/cuda/cuda_backend.cu)
            target_link_libraries(ibmbrute PRIVATE CUDA::cudart)
            set_target_properties(ibmbrute PROPERTIES
                CUDA_STANDARD 17
                CUDA_STANDARD_REQUIRED ON
            )
            set(IBMBRUTE_HAVE_CUDA_VALUE 1)
            set(IBMBRUTE_CUDA_STATUS "enabled (version ${CUDAToolkit_VERSION})")
        else()
            set(IBMBRUTE_CUDA_STATUS
                "disabled: CUDA compiler cannot compile C++17 host headers with the active host compiler")
        endif()
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

function(ibmbrute_configure_target target_name)
    target_compile_features(${target_name} PRIVATE cxx_std_17)

    if (MSVC)
        target_compile_options(${target_name} PRIVATE
            $<$<COMPILE_LANGUAGE:CXX,OBJCXX>:/W4>
            $<$<COMPILE_LANGUAGE:CXX,OBJCXX>:/permissive->
        )
    else()
        target_compile_options(${target_name} PRIVATE
            $<$<COMPILE_LANGUAGE:CXX,OBJCXX>:-Wall>
            $<$<COMPILE_LANGUAGE:CXX,OBJCXX>:-Wextra>
            $<$<COMPILE_LANGUAGE:CXX,OBJCXX>:-Wpedantic>
        )
    endif()

    target_compile_definitions(${target_name} PRIVATE
        IBMBRUTE_HAVE_METAL=${IBMBRUTE_HAVE_METAL_VALUE}
        IBMBRUTE_HAVE_CUDA=${IBMBRUTE_HAVE_CUDA_VALUE}
    )

    if (IBMBRUTE_CUDA_SOURCES)
        target_sources(${target_name} PRIVATE ${IBMBRUTE_CUDA_SOURCES})
        target_link_libraries(${target_name} PRIVATE CUDA::cudart)
        set_target_properties(${target_name} PROPERTIES
            CUDA_STANDARD 17
            CUDA_STANDARD_REQUIRED ON
            CUDA_ARCHITECTURES "75;86;89;120"
        )
    endif()
endfunction()

ibmbrute_configure_target(ibmbrute)

if (WIN32 AND IBMBRUTE_HAVE_CUDA_VALUE)
    add_executable(ibmbrute-win32 WIN32
        ${IBMBRUTE_COMMON_SOURCES}
        src/gui/win32_benchmark_dialog.cpp
        src/gui/win32_config_dialog.cpp
        src/gui/win32_gui.cpp
        src/gui/win32_gui.rc
    )
    target_compile_definitions(ibmbrute-win32 PRIVATE UNICODE _UNICODE)
    target_link_libraries(ibmbrute-win32 PRIVATE comctl32)
    if (MSVC)
        target_link_options(ibmbrute-win32 PRIVATE /MANIFEST:NO)
    endif()
    ibmbrute_configure_target(ibmbrute-win32)
endif()

message(STATUS "CUDA toolkit support: ${IBMBRUTE_CUDA_STATUS}")

enable_testing()
add_test(NAME ibmbrute_verify COMMAND ibmbrute --verify)
