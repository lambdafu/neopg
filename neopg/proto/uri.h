/* URI support
   Copyright 2017 The NeoPG developers

   NeoPG is released under the Simplified BSD License (see license.txt)
*/

#pragma once

#include <string>

#include <neopg/utils/common.h>

namespace NeoPG {

class NEOPG_DLL URI {
 public:
  std::string scheme;
  std::string authority;
  std::string userinfo;
  std::string host;
  std::string port;
  std::string path;
  std::string query;
  std::string fragment;

  URI() {}
  URI(const std::string& uri) { set_uri(uri); }
  URI& clear();
  URI& set_uri(const std::string& uri);
  std::string str();
};

}  // Namespace NeoPG
