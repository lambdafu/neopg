# NeoPG - cmake file
# Copyright 2017 The NeoPG developers
#
# NeoPG is released under the Simplified BSD License (see license.txt)

cmake_minimum_required(VERSION 3.2 FATAL_ERROR)

# Get version number before calling project().
list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake")
include(GitVersion)
set(NeoPG_VERSION_STRING "${GIT_VERSION_STRING}")
set(NeoPG_VERSION_STRING_FULL "${GIT_VERSION_STRING_FULL}")

project(NeoPG VERSION "${NeoPG_VERSION_STRING}" LANGUAGES CXX)
message(STATUS "${PROJECT_NAME} ${${PROJECT_NAME}_VERSION_STRING_FULL}")

# Add targets for maintainers: release, changelog
set(GitRelease_USER "das-labor")
set(GitRelease_PROJECT "neopg")
include(GitRelease)

# Add user-settable options.
option(BUILD_SHARED_LIBS "Build shared libraries." ON)


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

# Add all tests as dependencies to "tests" so the coverage target can
# depend on them.
add_custom_target(tests)

enable_testing()

# PEGTL
set(TAO-PEGTL_ROOT ${CMAKE_CURRENT_SOURCE_DIR}/3rdparty/pegtl)
set(PEGTL_INCLUDE_DIR ${TAO-PEGTL_ROOT}/include)
set(PEGTL_BUILD_TESTS OFF CACHE BOOL "")
add_subdirectory(${TAO-PEGTL_ROOT} EXCLUDE_FROM_ALL)


# Rang
set(RANG_ROOT ${CMAKE_CURRENT_SOURCE_DIR}/3rdparty/rang)
set(RANG_INCLUDE_DIR ${RANG_ROOT}/include)

# CLI11
set(CLI11_ROOT ${CMAKE_CURRENT_SOURCE_DIR}/3rdparty/CLI11)
set(CLI11_INCLUDE_DIR ${CLI11_ROOT}/include)

# Spdlog
set(SPDLOG_ROOT ${CMAKE_CURRENT_SOURCE_DIR}/3rdparty/spdlog)
set(SPDLOG_INCLUDE_DIR ${SPDLOG_ROOT}/include)

# json
set(TAOCPP-JSON_ROOT ${CMAKE_CURRENT_SOURCE_DIR}/3rdparty/json)
set(JSON_INCLUDE_DIR ${TAOCPP-JSON_ROOT}/include)
set(TAOCPP_JSON_BUILD_TESTS OFF CACHE BOOL "")
add_subdirectory(${TAOCPP-JSON_ROOT} EXCLUDE_FROM_ALL)

# CodeCoverage

include(ProcessorCount)
ProcessorCount(PROCESSOR_COUNT)

if(CMAKE_BUILD_TYPE MATCHES Debug)

  option(COVERAGE "Create coverage data")

  if(COVERAGE)

    include(CodeCoverage)
    APPEND_COVERAGE_COMPILER_FLAGS()

    set(COVERAGE_EXCLUDES '*/3rdparty/*' '*/usr/*' '*/nix/store/*')
    SETUP_TARGET_FOR_COVERAGE(
	 NAME coverage
	 EXECUTABLE ctest
	 DEPENDENCIES tests
    )
    SETUP_TARGET_FOR_COVERAGE_HTML(
	 NAME coverage-html
	 EXECUTABLE ctest
	 DEPENDENCIES tests
    )
    SETUP_TARGET_FOR_COVERAGE_COBERTURA(
	 NAME coverage-data
	 EXECUTABLE ctest
	 DEPENDENCIES tests
    )
  endif(COVERAGE)

endif(CMAKE_BUILD_TYPE MATCHES Debug)


# Doxygen

find_package(Doxygen)
option(BUILD_DOC "Create and install documentation (requires Doxygen)" ${DOXYGEN_FOUND})

if(BUILD_DOC)
    if(NOT DOXYGEN_FOUND)
        message(FATAL_ERROR "Doxygen is needed to build the documentation.")
    endif()

    set(DOXYFILE_IN ${CMAKE_CURRENT_SOURCE_DIR}/neopg-tool/Doxyfile.in)
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
pkg_check_modules(sqlite REQUIRED IMPORTED_TARGET sqlite3)
pkg_check_modules(botan-2 REQUIRED IMPORTED_TARGET botan-2)
pkg_check_modules(libusb-1.0 REQUIRED IMPORTED_TARGET libusb-1.0)
pkg_check_modules(gnutls REQUIRED IMPORTED_TARGET gnutls)

find_package(Boost COMPONENTS locale REQUIRED)

find_package(CURL REQUIRED)
find_package(Threads)

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/neopg-tool/config.h.in ${CMAKE_CURRENT_BINARY_DIR}/config.h)

add_subdirectory(neopg)
add_subdirectory(legacy)
add_subdirectory(neopg-tool)

install(EXPORT neopg NAMESPACE neopg:: DESTINATION lib/cmake/neopg)

# get all project files
file(GLOB_RECURSE ALL_SOURCE_FILES
     ${CMAKE_SOURCE_DIR}/legacy/*.cpp
     ${CMAKE_SOURCE_DIR}/legacy/*.h
     ${CMAKE_SOURCE_DIR}/include/*.cpp
     ${CMAKE_SOURCE_DIR}/include/*.h
     ${CMAKE_SOURCE_DIR}/lib/*.cpp
     ${CMAKE_SOURCE_DIR}/lib/*.h
     ${CMAKE_SOURCE_DIR}/src/*.cpp
     ${CMAKE_SOURCE_DIR}/src/*.h
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

