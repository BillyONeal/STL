# Copyright (c) Microsoft Corporation.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

find_package(re2 CONFIG REQUIRED)

add_executable(stltest stltest.cpp ../inc/stljobs.h)
target_link_libraries(stltest Userenv.lib Synchronization.lib re2::re2)
