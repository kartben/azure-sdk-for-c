# Copyright (c) Microsoft Corporation. All rights reserved.
# SPDX-License-Identifier: MIT

cmake_minimum_required (VERSION 3.10)

project (az_win32 LANGUAGES C)
set(CMAKE_C_STANDARD 99)

add_library(az_win32 STATIC)

target_link_libraries(az_win32 PRIVATE az_core)

target_sources(az_win32 PRIVATE src/az_win32.c)

