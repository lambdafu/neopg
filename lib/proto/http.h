/* HTTP Protocol support
   Copyright 2017 The NeoPG developers

   NeoPG is released under the Simplified BSD License (see license.txt)
*/

#pragma once

#include <curl/curl.h>
#include <tao/json/external/optional.hpp>
#include <map>
#include <regex>

#include <neopg/uri.h>

namespace NeoPG {

class NEOPG_UNSTABLE_API Http {
 public:
  static const long MAX_REDIRECTS_DEFAULT{2};
  static const long MAX_FILESIZE_DEFAULT{2 * 1024 * 1024};

  Http();

  Http& forbid_reuse(bool no_reuse = true);
  Http& set_url(const std::string& url);
  Http& set_proxy(const std::string& proxy);
  Http& default_proxy(bool allow_default = true);
  Http& set_redirects(long nr);
  Http& set_timeout(long milliseconds);
  Http& set_post(const tao::optional<std::string>& data = tao::nullopt);
  Http& set_post(const char* data, size_t len);
  Http& no_cache(bool no_cache = true);
  Http& set_cainfo(const std::string& pemfile);
  Http& set_connect_to(const std::string& host);
  Http& set_maxfilesize(long size);

  enum class Resolve : long {
    Any = CURL_IPRESOLVE_WHATEVER,
    IPv4 = CURL_IPRESOLVE_V4,
    IPv6 = CURL_IPRESOLVE_V6
  };
  Http& set_ipresolve(Resolve which = Resolve::Any);

  std::string fetch();

  std::string get_last_error() { return m_last_error; }

  /* Add header here.  */
  std::map<std::string, std::string> m_header;

 private:
  std::unique_ptr<CURL, void (*)(CURL*)> m_handle;
  std::string m_last_error;
  tao::optional<std::string> m_post_data;
  std::string m_connect_to;
  long m_maxfilesize;

  template <typename T>
  Http& set_opt(CURLoption opt, const T& val) {
    CURLcode cc = curl_easy_setopt(m_handle.get(), opt, val);
    if (cc != CURLE_OK) throw std::runtime_error(curl_easy_strerror(cc));
    return *this;
  }
  Http& set_opt_long(CURLoption opt, long val) { return set_opt<>(opt, val); }
  Http& set_opt_ptr(CURLoption opt, void* ptr) { return set_opt<>(opt, ptr); }
};

}  // Namespace NeoPG
