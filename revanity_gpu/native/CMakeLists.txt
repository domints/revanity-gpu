cmake_minimum_required(VERSION 3.20)
project(revanity_cuda LANGUAGES CXX CUDA)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CUDA_STANDARD 17)
set(CMAKE_CUDA_STANDARD_REQUIRED ON)

add_library(revanity_cuda SHARED revanity_cuda.cu)
set_target_properties(revanity_cuda PROPERTIES
    OUTPUT_NAME "revanity_cuda"
    CUDA_SEPARABLE_COMPILATION ON
)

if (MSVC)
    target_compile_definitions(revanity_cuda PRIVATE _CRT_SECURE_NO_WARNINGS)
endif()
