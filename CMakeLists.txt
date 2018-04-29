cmake_minimum_required(VERSION 2.6)

project(ftp)

set(TARGET tinyftp)
set(CMAKE_C_COMPILER  "gcc")

aux_source_directory(./src DIRSRCS)

find_library(LCRYPT  NAMES crypt)

add_executable(${TARGET} ${DIRSRCS})
target_link_libraries(${TARGET} ${LCRYPT})

install(TARGETS ${TARGET} DESTINATION ./bin)
