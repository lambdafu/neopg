// OpenPGP packet
// Copyright 2017-2018 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

#pragma once

#include <neopg/openpgp/packet_header.h>
#include <neopg/parser/parser_input.h>

#include <functional>
#include <memory>

namespace NeoPG {

using packet_header_factory = std::function<std::unique_ptr<PacketHeader>(
    PacketType type, uint32_t length)>;

struct NEOPG_UNSTABLE_API Packet {
  static std::unique_ptr<Packet> create_or_throw(PacketType type,
                                                 ParserInput& in);

  /// Use this to overwrite the default header.
  // FIXME: Replace this with a header-generator that comes in different
  // flavors, see issue #66.
  std::unique_ptr<PacketHeader> m_header;

  /// Write the packet to \p out. If \p m_header is set, use that. Otherwise,
  /// generate a default header using the provided factory.
  void write(std::ostream& out, packet_header_factory header_factory =
                                    NewPacketHeader::create_or_throw) const;

  /// Write the body of the packet to \p out.
  ///
  /// @param out The output stream to which the body is written.
  virtual void write_body(std::ostream& out) const = 0;

  /// Return the packet type.
  ///
  /// \return The tag of the packet.
  virtual PacketType type() const = 0;

  // Prevent memory leak when upcasting in smart pointer containers.
  virtual ~Packet() = default;
};

}  // namespace NeoPG
