// OpenPGP parser
// Copyright 2017-2018 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

#include <neopg/parser/openpgp.h>

#include <neopg/intern/cplusplus.h>
#include <neopg/intern/pegtl.h>

#include <functional>

using namespace NeoPG;
using namespace tao::neopg_pegtl;

namespace openpgp {

// The OpenPGP parser is stateful (due to the length field), so the state,
// grammar and actions are tightly coupled.
struct state {
  RawPacketSink& sink;
  PacketType packet_type;
  size_t packet_pos;
  std::unique_ptr<PacketHeader> header;
  std::unique_ptr<NewPacketLength> length;

  // The exception object if a packet could not be parsed.
  std::unique_ptr<ParserError> exc;

  // The length of the current packet body (or part of it).
  size_t packet_len;

  // This indicates that we have a partial packet data frame.
  bool partial;

  // This indicates that we have started a partial packet.
  bool started;

  state(RawPacketSink& a_sink) : sink(a_sink) {}
};

// A custom rule to match packet data.  This is stateful, because it requires
// the preceeding length information, and matches exactly st.packet_len bytes.
struct packet_body_data {
  using analyze_t = analysis::generic<analysis::rule_type::ANY>;
  template <apply_mode A, rewind_mode M, template <typename...> class Action,
            template <typename...> class Control, typename Input>
  static bool match(Input& in, state& st) {
    size_t available = in.size(st.packet_len);
    if (available >= st.packet_len) {
      in.bump(st.packet_len);
      return true;
    } else {
      uint32_t max = RawPacketParser::MAX_PARSER_BUFFER;
      available = in.size(max);
      if (st.packet_len > max && available == max) {
        // Best we can do at this point is to skip over the packet and set an
        // error.
        uint32_t skip = st.packet_len;
        while (skip > 0) {
          assert(skip >= available);
          in.bump(available);
          in.discard();
          skip -= available;
          uint32_t skip_this = max;
          if (skip < skip_this) skip_this = skip;
          available = in.size(skip_this);
          if (available < skip_this) {
            st.exc = NeoPG::make_unique<ParserError>(parser_error(
                "packet too short (while skipping too large packet)", in));
            skip = available;
            // Fallthrough for one last iteration.
          }
        }
        if (!st.exc)
          st.exc = NeoPG::make_unique<ParserError>(
              parser_error("packet too large", in));
        st.packet_len = 0;
        return true;
      } else {
        in.bump(available);
        in.discard();
        st.packet_len = 0;
        st.exc = NeoPG::make_unique<ParserError>(
            parser_error("packet too short", in));
        return true;
      }
    }
    // Not reached.
    return false;
  }
};  // namespace openpgp

// We discard the input buffer so that we do not need to account for the
// packet or length header in the max buffer size calculation (so we can use a
// power of two rather than a power of two plus a small number of bytes).
struct packet_body : seq<discard, packet_body_data> {};

// For old packets of indeterminate length, we set an arbitrary chunk size with
// the packet_body rule, and finish up with packet_body_data_rest.
#define INDETERMINATE_LENGTH_CHUNK_SIZE 8192

// We do not discard the input buffer here, as we come here after
// back-tracking from packet_body, and we want to preserve the data.
struct packet_body_data_rest : until<eof> {};

struct packet_body_indeterminate
    : seq<star<packet_body>, packet_body_data_rest> {};

struct old_packet_length_one : bytes<1> {};
struct old_packet_length_two : bytes<2> {};
struct old_packet_length_four : bytes<4> {};
// Action here sets the packet length to INDETERMINATE_LENGTH_CHUNK_SIZE.
struct old_packet_length_na : success {};

struct old_packet_tag : any {};

struct is_old_packet_with_length_one : at<uint8::mask_one<0x03, 0x00>> {};
struct is_old_packet_with_length_two : at<uint8::mask_one<0x03, 0x01>> {};
struct is_old_packet_with_length_four : at<uint8::mask_one<0x03, 0x02>> {};
struct is_old_packet_with_length_na : at<uint8::mask_one<0x03, 0x03>> {};

struct old_packet_with_length_one
    : seq<is_old_packet_with_length_one, old_packet_tag, old_packet_length_one,
          packet_body> {};
struct old_packet_with_length_two
    : seq<is_old_packet_with_length_two, old_packet_tag, old_packet_length_two,
          packet_body> {};
struct old_packet_with_length_four
    : seq<is_old_packet_with_length_four, old_packet_tag,
          old_packet_length_four, packet_body> {};
struct old_packet_with_length_na
    : seq<is_old_packet_with_length_na, old_packet_tag, old_packet_length_na,
          packet_body_indeterminate> {};

// Old packets have bit 6 clear.
struct is_old_packet : at<uint8::mask_one<0x40, 0x00>> {};

// For old packets, the length type is encoded in the tag.  We differentiate
// before consuming the tag.
struct old_packet
    : seq<is_old_packet,
          sor<old_packet_with_length_one, old_packet_with_length_two,
              old_packet_with_length_four, old_packet_with_length_na>> {};

struct new_packet_length_one : uint8::range<0x00, 0xbf> {};
struct new_packet_length_two : seq<uint8::range<0xc0, 0xdf>, any> {};
struct new_packet_length_partial : uint8::range<0xe0, 0xfe> {};
struct new_packet_length_five : seq<one<(char)0xff>, bytes<4>> {};

struct new_packet_data_partial : seq<new_packet_length_partial, packet_body> {};

struct new_packet_data_definite
    : seq<sor<new_packet_length_one, new_packet_length_two,
              new_packet_length_five>,
          packet_body> {};

// New packet data always ends with a definite length part, optionally
// preceeded by an arbitrary number of partial data parts.
struct new_packet_data
    : seq<star<new_packet_data_partial>, new_packet_data_definite> {};

// A new packet tag has the packet type in bit 0-5 (see action).
struct new_packet_tag : any {};

// A new packet tag has bit 6 set.
struct is_new_packet : at<uint8::mask_one<0x40, 0x40>> {};

// A new packet consists of a tag and one or more length and data parts.
struct new_packet : seq<is_new_packet, new_packet_tag, new_packet_data> {};

// Every packet starts with a tag that has bit 7 set.
struct is_packet : at<uint8::mask_one<0x80, 0x80>> {};

// A packet is either in the new or old format.
struct packet : seq<discard, is_packet, sor<new_packet, old_packet>> {};

// OpenPGP consists of a sequence of packets.
struct grammar : seq<until<eof, packet>, must<eof>> {};

template <typename Rule>
struct action : nothing<Rule> {};

template <>
struct action<old_packet_tag> {
  template <typename Input>
  static void apply(const Input& in, state& st) {
    auto val0 = (in.peek_byte() >> 2) & 0xf;
    st.packet_type = (PacketType)val0;
    st.packet_pos = in.position().byte;
  }
};

template <>
struct action<old_packet_length_one> {
  template <typename Input>
  static void apply(const Input& in, state& st) {
    auto match = in.begin();
    st.packet_len = in.peek_byte();
    st.header = NeoPG::make_unique<OldPacketHeader>(
        st.packet_type, st.packet_len, PacketLengthType::OneOctet);
    st.header->m_offset = st.packet_pos;
  }
};

template <>
struct action<old_packet_length_two> {
  template <typename Input>
  static void apply(const Input& in, state& st) {
    std::string str = in.string();
    st.packet_len = (in.peek_byte(0) << 8) + in.peek_byte(1);
    st.header = NeoPG::make_unique<OldPacketHeader>(
        st.packet_type, st.packet_len, PacketLengthType::TwoOctet);
    st.header->m_offset = st.packet_pos;
  }
};

template <>
struct action<old_packet_length_four> {
  template <typename Input>
  static void apply(const Input& in, state& st) {
    auto val0 = (uint32_t)in.peek_byte(0);
    auto val1 = (uint32_t)in.peek_byte(1);
    auto val2 = (uint32_t)in.peek_byte(2);
    auto val3 = (uint32_t)in.peek_byte(3);
    st.packet_len = (val0 << 24) + (val1 << 16) + (val2 << 8) + val3;
    st.header = NeoPG::make_unique<OldPacketHeader>(
        st.packet_type, st.packet_len, PacketLengthType::FourOctet);
    st.header->m_offset = st.packet_pos;
  }
};

template <>
struct action<old_packet_length_na> {
  template <typename Input>
  static void apply(const Input& in, state& st) {
    st.packet_len = INDETERMINATE_LENGTH_CHUNK_SIZE;
    st.header = NeoPG::make_unique<OldPacketHeader>(
        st.packet_type, st.packet_len, PacketLengthType::Indeterminate);
    st.header->m_offset = st.packet_pos;
    // Simulate a partial packet (we finish differently with
    // packet_body_data_rest).
    st.partial = true;
  }
};

// Extract packet type from new packet tag.
template <>
struct action<new_packet_tag> {
  template <typename Input>
  static void apply(const Input& in, state& st) {
    auto val0 = in.peek_byte() & 0x3f;
    st.packet_type = (PacketType)val0;
    st.packet_pos = in.position().byte;
  }
};

template <>
struct action<new_packet_length_one> {
  template <typename Input>
  static void apply(const Input& in, state& st) {
    st.packet_len = in.peek_byte();
    if (st.started == false) {
      st.header = NeoPG::make_unique<NewPacketHeader>(
          st.packet_type, st.packet_len, PacketLengthType::OneOctet);
      st.header->m_offset = st.packet_pos;
    } else {
      st.length = NeoPG::make_unique<NewPacketLength>(
          st.packet_len, PacketLengthType::OneOctet);
    }
    st.partial = false;
  }
};  // namespace openpgp

template <>
struct action<new_packet_length_two> {
  template <typename Input>
  static void apply(const Input& in, state& st) {
    st.packet_len = ((in.peek_byte() - 0xc0) << 8) + in.peek_byte(1) + 192;
    if (st.started == false) {
      st.header = NeoPG::make_unique<NewPacketHeader>(
          st.packet_type, st.packet_len, PacketLengthType::TwoOctet);
      st.header->m_offset = st.packet_pos;
    } else {
      st.length = NeoPG::make_unique<NewPacketLength>(
          st.packet_len, PacketLengthType::TwoOctet);
    }
    st.partial = false;
  }
};

template <>
struct action<new_packet_length_five> {
  template <typename Input>
  static void apply(const Input& in, state& st) {
    auto val0 = (uint32_t)in.peek_byte(1);
    auto val1 = (uint32_t)in.peek_byte(2);
    auto val2 = (uint32_t)in.peek_byte(3);
    auto val3 = (uint32_t)in.peek_byte(4);
    st.packet_len = (val0 << 24) + (val1 << 16) + (val2 << 8) + val3;
    if (st.started == false) {
      st.header = NeoPG::make_unique<NewPacketHeader>(
          st.packet_type, st.packet_len, PacketLengthType::FiveOctet);
      st.header->m_offset = st.packet_pos;
    } else {
      st.length = NeoPG::make_unique<NewPacketLength>(
          st.packet_len, PacketLengthType::FiveOctet);
    }
    st.partial = false;
  }
};

template <>
struct action<new_packet_length_partial> {
  template <typename Input>
  static void apply(const Input& in, state& st) {
    st.packet_len = 1 << (in.peek_byte() & 0x1f);
    // FIXME: Not necessary if started == true. Would save one allocation.
    if (st.started == false) {
      st.header = NeoPG::make_unique<NewPacketHeader>(
          st.packet_type, st.packet_len, PacketLengthType::Partial);
      st.header->m_offset = st.packet_pos;
    } else {
      st.length = NeoPG::make_unique<NewPacketLength>(
          st.packet_len, PacketLengthType::Partial);
    }
    st.partial = true;
  }
};

template <>
struct action<is_packet> {
  template <typename Input>
  static void apply(const Input& in, state& st) {
    st.packet_type = PacketType::Reserved;
    st.header.reset(nullptr);
    st.length.reset(nullptr);
    st.exc.reset(nullptr);
    st.partial = false;
    st.started = false;
  }
};

template <>
struct action<packet_body_data> {
  template <typename Input>
  static void apply(const Input& in, state& st) {
    const char* data = in.begin();
    size_t length = st.packet_len;

    if (!st.started) {
      if (!st.partial) {
        if (st.exc)
          st.sink.error_packet(std::move(st.header), std::move(st.exc));
        else
          st.sink.next_packet(std::move(st.header), data, length);
      } else {
        // At this point, we don't support error packets for partial packets,
        // because we can't skip them easily. The semantics would be unclear.
        if (st.exc) throw *st.exc;

        st.sink.start_packet(std::move(st.header));
        st.sink.continue_packet(nullptr, data, length);
      }
      st.started = true;
    } else {
      // At this point, we don't support error packets for partial packets,
      // because we can't skip them easily. The semantics would be unclear.
      if (st.exc) throw *st.exc;

      if (st.partial) {
        st.sink.continue_packet(std::move(st.length), data, length);
      } else {
        st.sink.finish_packet(std::move(st.length), data, length);
      }
    }
    // auto packet = NeoPG::make_unique::make_unique<NeoPG::RawPacket>();
    // st.sink.next_packet(std::move(packet));
    // //st.sink.next_packet(NeoPG::make_unique<NeoPG::RawPacket>(st.packet_type));
  }
};

template <>
struct action<packet_body_data_rest> {
  template <typename Input>
  static void apply(const Input& in, state& st) {
    const char* data = in.begin();
    size_t length = st.packet_len;
    st.sink.finish_packet(nullptr, data, length);
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
const std::string control<eof>::error_message = "input has trailing data";

}  // namespace openpgp

// FIXME: Pass filename to ParserInput (everywhere).
void RawPacketParser::process(Botan::DataSource& source) {
  using reader_t =
      std::function<std::size_t(char* buffer, const std::size_t length)>;

  auto state = openpgp::state{m_sink};
  auto reader = [this, &source, &state](
                    char* buffer, const std::size_t length) mutable -> size_t {
    size_t count = source.read(reinterpret_cast<uint8_t*>(buffer), length);
    return count;
  };
  buffer_input<reader_t> input("reader", MAX_PARSER_BUFFER, reader);

  parse<openpgp::grammar, openpgp::action, openpgp::control>(input, state);
}

void RawPacketParser::process(std::istream& source) {
  Botan::DataSource_Stream in{source};
  process(in);
}

void RawPacketParser::process(const std::string& source) {
  std::stringstream in{source};
  process(in);
}
