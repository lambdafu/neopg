/* NeoPG
   Copyright 2017 The NeoPG developers

   NeoPG is released under the Simplified BSD License (see license.txt)
*/

#include <iostream>

#include <neopg-tool/curl_command.h>
#include <neopg/http.h>

namespace NeoPG {

void CurlCommand::run() {
  NeoPG::Http request;
  request.set_url(m_url)
      .set_maxfilesize(m_max_filesize)
      .set_redirects(m_max_redirects)
      .no_cache(m_nocache);

  std::string response = request.fetch();
  std::cout.write((const char*)response.data(), response.size());
}

}  // Namespace NeoPG
