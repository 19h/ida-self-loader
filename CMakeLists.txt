cmake_minimum_required(VERSION 3.25)

if(DEFINED IDA_SDK_DIR)
    set(ENV{IDASDK} "${IDA_SDK_DIR}")
elseif(NOT DEFINED ENV{IDASDK})
    message(FATAL_ERROR
        "Set IDASDK to your IDA SDK checkout, or pass -DIDA_SDK_DIR=/path/to/ida-sdk")
endif()

include("$ENV{IDASDK}/src/cmake/idasdk_init.cmake")

project(self_loader VERSION 1.0.0 LANGUAGES CXX)

# Keep build products in this project instead of the SDK's bin directory.
if(NOT IDABIN)
    set(IDABIN "${CMAKE_BINARY_DIR}/bin")
endif()

find_package(idasdk REQUIRED)

ida_add_loader(self_loader
    SOURCES
        src/loader.cpp
        src/self_parser.cpp
        src/self_parser.hpp
)
target_include_directories(self_loader PRIVATE src)

include(CTest)
if(BUILD_TESTING)
    add_executable(self_parser_tests
        tests/self_parser_tests.cpp
        src/self_parser.cpp
        src/self_parser.hpp
    )
    target_include_directories(self_parser_tests PRIVATE src)
    target_compile_features(self_parser_tests PRIVATE cxx_std_17)
    if(MSVC)
        target_compile_options(self_parser_tests PRIVATE /W4)
    else()
        target_compile_options(self_parser_tests PRIVATE -Wall -Wextra -Wpedantic)
    endif()
    add_test(NAME self_parser_tests COMMAND self_parser_tests)
endif()
