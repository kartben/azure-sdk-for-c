# Copyright (c) Microsoft Corporation. All rights reserved.
# SPDX-License-Identifier: MIT

cmake_minimum_required (VERSION 3.10)

project(az_noplatform LANGUAGES C)
set(CMAKE_C_STANDARD 99)

add_library(az_noplatform STATIC)

target_link_libraries(az_noplatform PRIVATE az_core)

target_sources(az_noplatform PRIVATE src/az_noplatform.c)
