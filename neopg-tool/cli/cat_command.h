/* Command line parsing
   Copyright 2017 The NeoPG developers

   NeoPG is released under the Simplified BSD License (see license.txt)
*/

#pragma once

#include <neopg-tool/cli/command.h>

namespace NeoPG {

class CatCommand : public Command {
 public:
  std::vector<std::string> m_files;

  void run() override;
  CatCommand(CLI::App& app, const std::string& flag,
             const std::string& description, const std::string& group_name = "")
      : Command(app, flag, description, group_name) {
    m_cmd.add_option("file", m_files, "file to output");
  }
};

}  // Namespace NeoPG
