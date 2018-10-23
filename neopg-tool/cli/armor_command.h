/* Command line parsing
   Copyright 2017 The NeoPG developers

   NeoPG is released under the Simplified BSD License (see license.txt)
*/

#pragma once

#include <neopg-tool/cli/command.h>

namespace NeoPG {

class ArmorCommand : public Command {
 public:
  std::vector<std::string> m_files;
  bool m_decode{false};
  bool m_crc24{true};
  std::string m_title{"PGP ARMORED FILE"};

  void decode();
  void encode();
  void run() override;
  ArmorCommand(CLI::App& app, const std::string& flag,
               const std::string& description,
               const std::string& group_name = "")
      : Command(app, flag, description, group_name) {
    m_cmd.add_option("file", m_files, "file to output");
    m_cmd.add_flag("-d,--decode", m_decode, "decode already armored data");
    m_cmd.add_option("--title", m_title,
                     "header title (or empty string for no header)", true);
    m_cmd.add_flag_function("--no-checksum",
                            [this](size_t cnt) { this->m_crc24 = false; },
                            "do not add a CRC24 checksum at the end");
  }
};

}  // Namespace NeoPG
