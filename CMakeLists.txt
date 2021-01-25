# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

cmake_minimum_required(VERSION 3.12)

# project(<Your Project Name> VERSION 1.0 LANGUAGES CXX)

project(SEALExamples VERSION 1.0 LANGUAGES CXX)

# If not called from root CMakeLists.txt

if(NOT DEFINED SEAL_BUILD_EXAMPLES)
    set(SEAL_BUILD_EXAMPLES ON)

    # Import Microsoft SEAL
    find_package(SEAL 3.6.1 EXACT REQUIRED)

    set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/bin)
endif()

if(SEAL_BUILD_EXAMPLES)

# add_executable(<Your Project Name>)
    add_executable(Sealtest)

# target_sources(<Your Project Name>)

    target_sources(Sealtest
        PRIVATE
        	${CMAKE_CURRENT_LIST_DIR}/examples.h
            ${CMAKE_CURRENT_LIST_DIR}/sealtest.cpp
            ${CMAKE_CURRENT_LIST_DIR}/encoder.cpp
            ${CMAKE_CURRENT_LIST_DIR}/bfv_Basics.cpp
    )

# target_link_libraries(<Your Project Name> PRIVATE SEAL::seal)
    if(TARGET SEAL::seal)
        target_link_libraries(Sealtest PRIVATE SEAL::seal)
    elseif(TARGET SEAL::seal_shared)
        target_link_libraries(Sealtest PRIVATE SEAL::seal_shared)
    else()
        message(FATAL_ERROR "Cannot find target SEAL::seal or SEAL::seal_shared")
    endif()
endif()
