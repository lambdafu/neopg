// OpenPGP multiprecision integer
// Copyright 2018 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

#pragma once

#include <neopg/parser/parser_input.h>

#include <memory>
#include <vector>

namespace NeoPG {

/// [Multiprecision integer](https://tools.ietf.org/html/rfc4880#section-3.2)
/// values.
class NEOPG_UNSTABLE_API MultiprecisionInteger {
 public:
  uint16_t m_length{0};
  std::vector<uint8_t> m_bits;

  /// Fill the instance from the input.
  /// @param input parser input with mpi data
  /// Throws ParserError if input can not be parsed.
  void parse(ParserInput& in);

  /// @return the length in bits
  uint16_t length() const noexcept { return m_length; }

  /// @return the mpi data
  const std::vector<uint8_t>& bits() const noexcept { return m_bits; }

  /// Write the mpi to the output stream.
  /// @param out output stream
  void write(std::ostream& out) const;

  MultiprecisionInteger() = default;
  MultiprecisionInteger(uint64_t nr);
};

inline bool operator==(const MultiprecisionInteger& lhs,
                       const MultiprecisionInteger& rhs) {
  return lhs.m_length == rhs.m_length && lhs.m_bits == rhs.m_bits;
}
}  // namespace NeoPG
