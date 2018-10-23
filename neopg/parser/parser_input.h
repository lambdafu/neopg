// OpenPGP parser input
// Copyright 2017-2018 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

/// \file
/// This file contains support for parser input.

#pragma once

#include <neopg/utils/common.h>

#include <memory>
#include <string>

namespace NeoPG {

// We wrap PEGTL memory_input, because we have to pass it around in public
// interfaces, and we don't want to expose the (template) type.
class NEOPG_UNSTABLE_API ParserInput {
 public:
  class Impl;
  // propagate_const?
  std::unique_ptr<Impl> m_impl;

  ParserInput(const char* data, size_t length, const std::string& source = "-");
  ParserInput(const uint8_t* data, size_t length,
              const std::string& source = "-")
      : ParserInput{reinterpret_cast<const char*>(data), length, source} {}
  ParserInput(std::string str) : ParserInput{str.data(), str.length(), "-"} {};

  // We need to define the destructor somewhere the Impl is defined.
  ~ParserInput();

  const char* current() const noexcept;
  size_t size();
  size_t position() const;
  void bump(const std::size_t in_count = 1) noexcept;

  /// Throw parse error exception at current position.
  void error(const std::string& message);

  /// Create a Mark to reset the input position when the mark goes out of scope.
  class Mark {
   public:
    class Impl;
    std::unique_ptr<Impl> m_impl;
    Mark(ParserInput& in);
    ~Mark();
  };
};

}  // namespace NeoPG
