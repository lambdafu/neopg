/* Command line parsing
   Copyright 2017 The NeoPG developers

   NeoPG is released under the Simplified BSD License (see license.txt)
*/

#pragma once

#include <neopg-tool/cli/command.h>

namespace NeoPG {

class RandomCommand : public Command {
 public:
  int m_count{0};
  void run() override;
  RandomCommand(CLI::App& app, const std::string& flag,
                const std::string& description,
                const std::string& group_name = "")
      : Command(app, flag, description, group_name) {
    m_cmd.add_option("count", m_count,
                     "number of bytes to output (or infinite)");
  }
  virtual ~RandomCommand() {}
};

}  // Namespace NeoPG
