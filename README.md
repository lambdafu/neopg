[![Gitter](https://badges.gitter.im/das-labor/neopg.svg)](https://gitter.im/das-labor/neopg)
[![Build Status](https://travis-ci.org/das-labor/neopg.svg?branch=master)](https://travis-ci.org/das-labor/neopg)
[![Code Coverage](https://codecov.io/gh/das-labor/neopg/branch/master/graph/badge.svg)](https://codecov.io/gh/das-labor/neopg)

# NeoPG implements the OpenPGP standard.

NeoPG is written in C++11.  It starts out as an opinionated fork of
the GnuPG code base, and hopefully will evolve to something entirely
different.

For now, many parts of NeoPG are licensed by the upstream authors
under various licenses, including GPL and LGPL variants.  Please refer
to the copyright notice at the top of every file.

New source code contributed by the NeoPG authors is licensed under the
permissive `Simplified BSD` license (the same license as Botan, the
cryptography library we want to use).

AT THIS TIME, THE COMPLETE WORK IS NECESSARILY LICENSED UNDER THE MOST
RESTRICTIVE LICENSE OF ANY OF ITS PARTS, THE GPLv3.  See the file
license.txt for details.

The dependencies are also released under their respective various
licenses.

## Installation

### Supported Compiler Versions

* Ubuntu 14.04.5 LTS: GCC 4.9, 5, 6, 7
* Ubuntu 14.04.5 LTS: Clang 3.5, 3.6, 3.7, 3.8, 3.9, 4.0, 5.0
* MacOS: Xcode 6.4, 7.3, 8.3, 9.1

GCC 4.8 is not supported (see [nlohmann/json](https://github.com/nlohmann/json)).

### Dependencies

Aside from a working C++ toolchain you'll need the following libraries.

1. CMake >= 3.2
2. SQLite >= 3.0
3. Botan >= 2.0 --with-zlib --with-bzip2
4. Boost >= 1.64.0
5. gettext-tools

### Make

With all dependencies installed NeoPG can be build with CMake.

```bash
$ git submodule update --init
$ mkdir build
$ cd build
$ cmake ..
$ make
$ make test # opt: ARGS=-V or CTEST_OUTPUT_ON_FAILURE=1
```

Select your compiler and language version by setting CXX and CXXSTD
environment variables, e.g.:

```bash
$ CXX=clang++-5 CXXSTD=14 cmake ..
```

### Development

Development builds have extra dependencies:

1. gcovr (make coverage)
2. clang-format (make pretty)
3. cppcheck (make lint; TODO: Replace with cmake-tidy?)
4. doxygen (make doc)

To enable a debug build, set the CMAKE_BUILD_TYPE flag (default is `Release`):

```bash
# cmake -DCMAKE_BUILD_TYPE=Debug -DCOVERAGE=ON ..
# make coverage
```

Other targets:

```
$ make pretty        # Run clang-format on all source files
$ make lint          # Run cppcheck
$ make coverage      # Just coverage.info for codecov.io
$ make coverage-html # Local HTML report
$ make coverage-data # Cobertura XML report
```

## TODO

* format strings for list-keys etc

Code metrics:
- sloccount, git-loc
- secretgrind
- sonarqube

Windows
- chocolatey

macOS
- brew (homebrew)

openpgp profile
- ascii armor default
- auto keylocate default auto keyretrieve
- dirmngr: hkps connections should default to system trust if --hkp-cacert is not given

## Hacking

### Fedora
To get started on a Fedora 26, do the following

```
# Fedora 26 only comes with Botan 1.10. Here we enable a copr repo for Botan 2
$ sudo dnf copr enable bkircher/botan2

# Install dev dependencies
$ sudo dnf install -y \
    boost-devel \
    botan2-devel \
    cmake \
    gcc-c++ \
    gcovr \
    git \
    lcov \
    libusb-devel \
    python \
    sqlite-devel \

# Clone repo and build
$ git clone --recursive git@github.com:das-labor/neopg.git
$ cd neopg/build
$ cmake ..
$ make
```

### macOS

To get started on macOS, follow these steps.
For the dependencies use a package manager like [Homebrew](https://brew.sh):

```
$ brew install botan boost cmake doxygen gettext
```

Build it!

```
# Clone repo and build
$ git clone --recursive git@github.com:das-labor/neopg.git
$ cd neopg/build
$ cmake ..
$ make
```

Have fun!
