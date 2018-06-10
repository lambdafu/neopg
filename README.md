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

Note: As we are using libcurl, you might have to pay attention to
possible license incompatibilities between the GPL as used by the
legacy gnupg code and the TLS library linked to libcurl.  In the
future, when libcurl supports Botan as TLS option, we might include a
copy and link statically to make this easier.

## Status

Currently, NeoPG is under development, and in an exploratory phase.
No promises are made about the stability, functionality, and security
of the development releases "0.0.x".  I am actively seeking feedback
and guidance for the API design and scope of functionality from users
and application developers.

From a purely practical point, the software should build and run, and
a lot of legacy functionality is available through the "gpg2",
"gpg-agent", "dirmngr" etc. subcommands.  New subcommands are introduced as
functionality is added or replaced.

From an organizational point of view, this is currently a one-man
project without third-party funding.  A significant amount of time is
spent on developing a more substantial basis for the project.  So you
will see periods of coding activity, but also periods of
organizational activity (such as talks, and grant application
writing).

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
5. libcurl >= 7.49.0
6. gettext-tools

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

### Legacy support

You can create links to the `neopg` binary under a name that ends with
a legacy subcommand.  If called through such a link, `neopg` will
invoke that subcommand directly.  For example, `neo-gpg2 --version`
would be the same as `neopg gpg2 --version`, and so on.  Examples for
names that would behave that way are `neopg-gpg2`, `neo-gpg2`,
`neogpg2`, `gpg2` etc.  Here is a list of supported endings:

| Ending           | Subcommand       |
| ---------------- | ---------------- |
| `gpg`            | `gpg2`           |
| `gpg2`           | `gpg2`           |
| `agent`          | `agent`          |
| `scd`            | `scd`            |
| `dirmngr`        | `dirmngr`        |
| `dirmngr-client` | `dirmngr-client` |

## Development

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
To get started on Fedora 28, or later, do the following.

```
# Install dev dependencies
$ sudo dnf install -y \
    boost-devel \
    botan2-devel \
    cmake \
    gcc-c++ \
    gcovr \
    git \
    gnutls-devel \
    lcov \
    libusbx-devel \
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

By default homebrew does not link the gettext binaries into the path, to enforce
this:

```
$ brew link gettext --force
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
