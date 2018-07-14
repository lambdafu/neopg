/* Command line parsing
   Copyright 2017 The NeoPG developers

   NeoPG is released under the Simplified BSD License (see license.txt)
*/

#pragma once

#include <neopg-tool/command.h>
#include <neopg/http.h>

namespace NeoPG {

class CurlCommand : public Command {
 public:
  long m_max_filesize{NeoPG::Http::MAX_FILESIZE_DEFAULT};
  long m_max_redirects{NeoPG::Http::MAX_REDIRECTS_DEFAULT};
  bool m_nocache{false};
  std::string m_url;
  void run() override;
  CurlCommand(CLI::App& app, const std::string& flag,
              const std::string& description,
              const std::string& group_name = "")
      : Command(app, flag, description, group_name) {
    m_cmd.add_option("url", m_url, "URL of resource to fetch")->required();
    m_cmd.add_option("--max-redirs", m_max_redirects,
                     "maximum number of redirects", true);
    m_cmd.add_option("--max-filesize", m_max_filesize, "maximum file size",
                     true);
    m_cmd.add_flag("--no-cache", m_nocache, "do not use proxy data");
  }
};

}  // Namespace NeoPG
