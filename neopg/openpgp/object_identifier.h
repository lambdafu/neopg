// OpenPGP object identifier
// Copyright 2018 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

#pragma once

#include <neopg/parser/parser_input.h>

#include <memory>
#include <vector>

namespace NeoPG {

/// [ObjectIdentifier](https://tools.ietf.org/html/rfc6637#section-11)
class NEOPG_UNSTABLE_API ObjectIdentifier {
 public:
  std::vector<uint8_t> m_data;

  /// Fill the instance from the input.
  /// @param input parser input with mpi data
  /// Throws ParserError if input can not be parsed.
  void parse(ParserInput& in);

  /// @return the length in bytes
  uint16_t length() const noexcept { return m_data.size(); }

  /// @return the octed data
  const std::vector<uint8_t>& data() const noexcept { return m_data; }

  /// Write the mpi to the output stream.
  /// @param out output stream
  void write(std::ostream& out) const;

  const std::string as_string() const;

  ObjectIdentifier() = default;
};

inline bool operator==(const ObjectIdentifier& lhs,
                       const ObjectIdentifier& rhs) {
  return lhs.m_data == rhs.m_data;
}
}  // namespace NeoPG
