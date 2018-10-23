// OpenPGP multiprecision integer (implementation)
// Copyright 2018 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

#include <neopg/openpgp/multiprecision_integer.h>

#include <neopg/intern/cplusplus.h>
#include <neopg/intern/pegtl.h>

#include <botan/bigint.h>

using namespace NeoPG;

namespace NeoPG {
namespace mpi {
using namespace pegtl;

struct length : bytes<2> {};

// Custom rule to match as many octets as are indicated by length.
struct bits {
  using analyze_t = analysis::generic<analysis::rule_type::ANY>;
  template <apply_mode A, rewind_mode M, template <typename...> class Action,
            template <typename...> class Control, typename Input>
  static bool match(Input& in, MultiprecisionInteger& mpi) {
    uint16_t length = (mpi.length() + 7) / 8;
    if (in.size(length) >= length) {
      // FIXME: Validate high bits?
      in.bump(length);
      return true;
    }
    return false;
  }
};

struct grammar : must<length, bits> {};

template <typename Rule>
struct action : nothing<Rule> {};

template <>
struct action<length> {
  template <typename Input>
  static void apply(const Input& in, MultiprecisionInteger& mpi) {
    auto val0 = (uint16_t)in.peek_byte(0);
    auto val1 = (uint16_t)in.peek_byte(1);
    mpi.m_length = (val0 << 8) + val1;
  }
};

template <>
struct action<bits> {
  template <typename Input>
  static void apply(const Input& in, MultiprecisionInteger& mpi) {
    auto begin = reinterpret_cast<const uint8_t*>(in.begin());
    mpi.m_bits.assign(begin, begin + in.size());
  }
};

// Control
template <typename Rule>
struct control : pegtl::normal<Rule> {
  static const std::string error_message;

  template <typename Input, typename... States>
  static void raise(const Input& in, States&&...) {
    throw parser_error(error_message, in);
  }
};

template <>
const std::string control<length>::error_message = "mpi length is invalid";

template <>
const std::string control<bits>::error_message = "mpi bits are invalid";

}  // namespace mpi
}  // namespace NeoPG

void MultiprecisionInteger::write(std::ostream& out) const {
  out << static_cast<uint8_t>(m_length >> 8) << static_cast<uint8_t>(m_length);
  out.write(reinterpret_cast<const char*>(m_bits.data()), m_bits.size());
}

void MultiprecisionInteger::parse(ParserInput& in) {
  pegtl::parse<mpi::grammar, mpi::action, mpi::control>(in.m_impl->m_input,
                                                        *this);
}

MultiprecisionInteger::MultiprecisionInteger(uint64_t nr) {
  auto bigint = Botan::BigInt{nr};
  m_length = bigint.bits();
  m_bits = Botan::BigInt::encode(bigint);
}
