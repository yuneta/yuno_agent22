##############################################
#   CMake
##############################################
project(yuneta_agent22 C)
cmake_minimum_required(VERSION 3.0)
include(CheckIncludeFiles)
include(CheckSymbolExists)

set(BIN_DEST_DIR /yuneta/agent)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -std=c99")

if(CMAKE_BUILD_TYPE MATCHES Debug)
  add_definitions(-DDEBUG)
  option(SHOWNOTES "Show preprocessor notes" OFF)

  if(CMAKE_COMPILER_IS_GNUCC)
    # GCC specific debug options
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O0 -g3 -ggdb3 -gdwarf-2")
    set(AVOID_VERSION -avoid-version)
  endif(CMAKE_COMPILER_IS_GNUCC)
endif(CMAKE_BUILD_TYPE MATCHES Debug)

add_definitions(-D_GNU_SOURCE)
add_definitions(-D_LARGEFILE_SOURCE -D_FILE_OFFSET_BITS=64)

check_include_files(regex.h HAVE_REGEX_H)
if(HAVE_REGEX_H)
    add_definitions(-DHAVE_REGEX_H)
else(HAVE_REGEX_H)
    message("***  WARNING: GNU C regex library not found.")
endif(HAVE_REGEX_H)

include_directories(/yuneta/development/output/include)

##############################################
#   Source
##############################################

SET (YUNO_SRCS
    src/main.c
    src/yuno_yuneta_agent22.c
    src/c_agent22.c
    src/c_pty.c
)
SET (YUNO_HDRS
    src/yuno_yuneta_agent22.h
    src/c_agent22.h
    src/c_pty.h
)

##############################################
#   yuno
##############################################
ADD_EXECUTABLE(yuneta_agent22 ${YUNO_SRCS} ${YUNO_HDRS})

TARGET_LINK_LIBRARIES(yuneta_agent22
    /yuneta/development/output/lib/libyuneta-tls.a
    /yuneta/development/output/lib/libyuneta-core.a
    /yuneta/development/output/lib/libginsfsm.a
    /yuneta/development/output/lib/libytls.a
    /yuneta/development/output/lib/libghelpers.a
    /yuneta/development/output/lib/libuv.a
    /yuneta/development/output/lib/liboauth2.a
    /yuneta/development/output/lib/libcjose.a
    /yuneta/development/output/lib/libjansson.a
    /yuneta/development/output/lib/libunwind.a
    /yuneta/development/output/lib/libpcre2-8.a
    /yuneta/development/output/lib/libcurl.a  # used by liboauth2
    /yuneta/development/output/lib/libssl.a
    /yuneta/development/output/lib/libcrypto.a

    pthread dl  # used by libuv
    lzma        # used by libunwind
    z rt m
    uuid
    util        # used by c_pty
)

##############################################
#   Installation
##############################################
install(
    TARGETS yuneta_agent22
    PERMISSIONS
    OWNER_READ OWNER_WRITE OWNER_EXECUTE
    GROUP_READ GROUP_WRITE GROUP_EXECUTE
    WORLD_READ WORLD_EXECUTE
    DESTINATION ${BIN_DEST_DIR}
)

# compile in Release mode optimized but adding debug symbols, useful for profiling :
#
#     cmake -DCMAKE_BUILD_TYPE=RelWithDebInfo ..
#
# or compile with NO optimization and adding debug symbols :
#
#     cmake -DCMAKE_BUILD_TYPE=Debug ..
#
#