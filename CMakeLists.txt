# NeoPG - tests
#   Copyright 2017 The NeoPG developers
#
# NeoPG is released under the Simplified BSD License (see license.txt)

# Cmake setup.
cmake_minimum_required(VERSION 3.2 FATAL_ERROR)
list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake")
include(GitVersion)
set(NeoPG_VERSION_STRING "${GIT_VERSION_STRING}")
set(NeoPG_VERSION_STRING_FULL "${GIT_VERSION_STRING_FULL}")

project(NeoPG VERSION "${NeoPG_VERSION_STRING}")
message(STATUS "${PROJECT_NAME} ${${PROJECT_NAME}_VERSION_STRING_FULL}")

# targets: release, changelog
include(GitRelease)

# Compiler setup.

set(CXXSTD 11)
if(DEFINED ENV{CXXSTD})
  set(CXXSTD $ENV{CXXSTD})
endif()
set(CMAKE_CXX_STANDARD ${CXXSTD})
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if (APPLE)
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -D_DARWIN_C_SOURCE")
endif()

# Google Test
set(GTEST_ROOT ${CMAKE_CURRENT_SOURCE_DIR}/3rdparty/googletest/googletest/)
set(GTEST_INCLUDE_DIR ${GTEST_ROOT}/include)
if(${CMAKE_HOST_SYSTEM_NAME} STREQUAL "Windows")
  set(gtest_force_shared_crt ON CACHE BOOL
    "Use shared (DLL) run-time lib even when Google Test is built as static lib.")
endif()
add_subdirectory(${GTEST_ROOT} EXCLUDE_FROM_ALL)
add_library(GTest::GTest ALIAS gtest)
add_library(GTest::Main ALIAS gtest_main)

enable_testing()

# PEGTL
set(PEGTL_ROOT ${CMAKE_CURRENT_SOURCE_DIR}/3rdparty/pegtl)
set(PEGTL_INCLUDE_DIR ${PEGTL_ROOT}/include)
set(PEGTL_BUILD_TESTS OFF CACHE BOOL "")
add_subdirectory(${PEGTL_ROOT} EXCLUDE_FROM_ALL)


# Rang
set(RANG_ROOT ${CMAKE_CURRENT_SOURCE_DIR}/3rdparty/rang)
set(RANG_INCLUDE_DIR ${RANG_ROOT}/include)
add_subdirectory(${RANG_ROOT} EXCLUDE_FROM_ALL)

# CLI11
set(CLI11_ROOT ${CMAKE_CURRENT_SOURCE_DIR}/3rdparty/CLI11)
set(CLI11_INCLUDE_DIR ${CLI11_ROOT}/include)

# json
set(JSON_ROOT ${CMAKE_CURRENT_SOURCE_DIR}/3rdparty/json)
set(JSON_INCLUDE_DIR ${JSON_ROOT}/include)

# CodeCoverage

include(ProcessorCount)
ProcessorCount(PROCESSOR_COUNT)

if(CMAKE_BUILD_TYPE MATCHES Debug)

include(CodeCoverage)
APPEND_COVERAGE_COMPILER_FLAGS()

set(COVERAGE_EXCLUDES '*/3rdparty/*' '*/usr/*' '*/nix/store/*')
SETUP_TARGET_FOR_COVERAGE(
     NAME coverage
     EXECUTABLE test-neopg
     DEPENDENCIES neopg
)
SETUP_TARGET_FOR_COVERAGE_HTML(
     NAME coverage-html
     EXECUTABLE test-neopg
     DEPENDENCIES neopg
)
SETUP_TARGET_FOR_COVERAGE_COBERTURA(
     NAME coverage-data
     EXECUTABLE test-neopg
     DEPENDENCIES neopg
)

endif(CMAKE_BUILD_TYPE MATCHES Debug)


# Doxygen

find_package(Doxygen)
option(BUILD_DOC "Create and install documentation (requires Doxygen)" ${DOXYGEN_FOUND})

if(BUILD_DOC)
    if(NOT DOXYGEN_FOUND)
        message(FATAL_ERROR "Doxygen is needed to build the documentation.")
    endif()

    set(DOXYFILE_IN ${CMAKE_CURRENT_SOURCE_DIR}/src/Doxyfile.in)
    set(DOXYFILE ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile)

    configure_file(${DOXYFILE_IN} ${DOXYFILE} @ONLY)
    message("Doxygen build started")

    add_custom_target(doc
        COMMAND ${DOXYGEN_EXECUTABLE} ${DOXYFILE}
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
        COMMENT "Generating documentation with Doxygen"
        VERBATIM)

    # install(DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/html DESTINATION share/doc)
endif()

find_package(PkgConfig)
pkg_check_modules(SQLITE3 REQUIRED sqlite3)
pkg_check_modules(BOTAN2 REQUIRED botan-2)
pkg_check_modules(LIBUSB REQUIRED libusb-1.0)
pkg_check_modules(GNUTLS REQUIRED gnutls)

include(CheckIncludeFiles)
check_include_files(malloc.h HAVE_MALLOC_H)

include (CheckFunctionExists)
check_function_exists (log HAVE_LOG)
check_function_exists (exp HAVE_EXP)

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/src/config.h.in ${CMAKE_CURRENT_BINARY_DIR}/config.h)

add_subdirectory(${CMAKE_SOURCE_DIR}/legacy)
add_subdirectory(${CMAKE_SOURCE_DIR}/lib)
add_subdirectory(${CMAKE_SOURCE_DIR}/src)
add_subdirectory(${CMAKE_SOURCE_DIR}/tests)


# get all project files
file(GLOB_RECURSE ALL_SOURCE_FILES
     ${CMAKE_SOURCE_DIR}/legacy/*.cpp
     ${CMAKE_SOURCE_DIR}/legacy/*.h
     ${CMAKE_SOURCE_DIR}/src/*.cpp
     ${CMAKE_SOURCE_DIR}/src/*.h
     ${CMAKE_SOURCE_DIR}/include/*.cpp
     ${CMAKE_SOURCE_DIR}/include/*.h
     ${CMAKE_SOURCE_DIR}/tests/*.cpp
     ${CMAKE_SOURCE_DIR}/tests/*.h
)

# additional target to perform cppcheck run, requires cppcheck

add_custom_target(
  lint
  COMMAND cppcheck
  --enable=warning,performance,portability,information,missingInclude
  --std=c++11
  --language=c++
  --verbose
  --quiet
  ${ALL_SOURCE_FILES}
)

# additional target to perform clang-format run, requires clang-format

find_program(CLANG_FORMAT NAMES clang-format-4.0 clang-format)
add_custom_target(
  pretty
  COMMAND ${CLANG_FORMAT} --version
  COMMAND ${CLANG_FORMAT} -style=file -i ${ALL_SOURCE_FILES}
)


#if(CMAKE_COMPILER_IS_GNUCXX)
#  target_compile_options(foo
#  PUBLIC -fno-...)
#endif()
#target_compile_features(foo
#PUBLIC cxx_auto_type
#PRIVATE
#cxx_variadic_templates)
