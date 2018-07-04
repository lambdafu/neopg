/* NeoPG
   Copyright 2017 The NeoPG developers

   NeoPG is released under the Simplified BSD License (see license.txt)
*/

#include <neopg-tool/packet_command.h>

#include <neopg/marker_packet.h>
#include <neopg/openpgp.h>
#include <neopg/parser_error.h>
#include <neopg/user_id_packet.h>

#include <botan/data_snk.h>
#include <botan/data_src.h>
#include <botan/hex.h>

#include <botan/ber_dec.h>
#include <botan/oids.h>

#include <CLI11.hpp>

#include <spdlog/fmt/fmt.h>

#include <rang.hpp>

#include <tao/json.hpp>

#include <iostream>

using namespace NeoPG;

void MarkerPacketCommand::run() {
  MarkerPacket packet;
  packet.write(std::cout);
}

void UserIdPacketCommand::run() {
  UserIdPacket packet;
  packet.m_content = m_uid;
  packet.write(std::cout);
}

struct LegacyPacketSink : public RawPacketSink {
  void next_packet(std::unique_ptr<PacketHeader> header, const char* data,
                   size_t length) {
    assert(length == header->length());
    size_t offset = header->m_offset;
    try {
      ParserInput in{data, length};
      auto packet = Packet::create_or_throw(header->type(), in);
      packet->m_header = std::move(header);
      packet->write(std::cout);
    } catch (ParserError& exc) {
      exc.m_pos.m_byte += offset;
      std::cerr << rang::style::bold << rang::fgB::red << "ERROR"
                << rang::style::reset << ":" << exc.as_string() << "\n";
      // FIXME: Add option to suppress errorneous output.
      header->write(std::cout);
      std::cout.write(data, length);
    }
  }

  void start_packet(std::unique_ptr<PacketHeader> header) {
    header->write(std::cout);
  }
  void continue_packet(std::unique_ptr<NewPacketLength> length_info,
                       const char* data, size_t length) {
    if (length_info) length_info->write(std::cout);
    std::cout.write(data, length);
  }
  void finish_packet(std::unique_ptr<NewPacketLength> length_info,
                     const char* data, size_t length) {
    continue_packet(std::move(length_info), data, length);
  }

  void error_packet(std::unique_ptr<PacketHeader> header,
                    std::unique_ptr<ParserError> exc) {
    std::cerr << rang::style::bold << rang::fgB::red << "ERROR"
              << rang::style::reset << ":" << exc->as_string() << "\n";
  };
};

static void process_msg(Botan::DataSource& source, Botan::DataSink& out) {
  out.start_msg();
  LegacyPacketSink sink;
  RawPacketParser parser(sink);

  try {
    parser.process(source);
  } catch (const ParserError& exc) {
    std::cerr << rang::style::bold << rang::fgB::red << "ERROR"
              << rang::style::reset
              << ":unrecoverable error:" << exc.as_string() << "\n";
  }
  out.end_msg();
}

void FilterPacketCommand::run() {
  Botan::DataSink_Stream out{std::cout};

  if (m_files.empty()) m_files.emplace_back("-");
  for (auto& file : m_files) {
    if (file == "-") {
      Botan::DataSource_Stream in{std::cin};
      process_msg(in, out);
    } else {
      // Open in binary mode.
      Botan::DataSource_Stream in{file, true};
      process_msg(in, out);
    }
  }
}

PacketCommand::PacketCommand(CLI::App& app, const std::string& flag,
                             const std::string& description,
                             const std::string& group_name)
    : Command(app, flag, description, group_name),
      cmd_marker(m_cmd, "marker", "output a Marker Packet", group_write),
      cmd_uid(m_cmd, "uid", "output a User ID Packet", group_write),
      cmd_filter(m_cmd, "filter", "process packet data", group_process),
      cmd_dump(m_cmd, "dump", "convert packet data", group_process) {}

void PacketCommand::run() {
  if (m_cmd.get_subcommands().empty()) throw CLI::CallForHelp();
}
