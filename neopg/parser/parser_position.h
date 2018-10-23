// OpenPGP parser position
// Copyright 2017-2018 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

/// \file
/// This file contains support for parser errors.

#pragma once

#include <neopg/utils/common.h>

#include <ostream>
#include <sstream>
#include <string>

namespace NeoPG {

class NEOPG_UNSTABLE_API ParserPosition {
 public:
  ParserPosition(const std::string& source, size_t byte)
      : m_source(source), m_byte(byte) {}

  std::string m_source;
  size_t m_byte{0};

  std::string as_string() const {
    std::stringstream out;
    out << m_source << ':' << m_byte;
    return out.str();
  }
};

}  // namespace NeoPG
