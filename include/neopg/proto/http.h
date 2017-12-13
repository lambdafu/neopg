/* HTTP Protocol support
   Copyright 2017 The NeoPG developers

   NeoPG is released under the Simplified BSD License (see license.txt)
*/

#pragma once

#include <curl/curl.h>
#include <boost/optional.hpp>
#include <map>
#include <regex>

#include <neopg/proto/uri.h>

namespace NeoPG {
namespace Proto {

class Http {
  const long MAX_REDIRECTS_DEFAULT = 2;

 public:
  Http();

  Http& forbid_reuse(bool no_reuse = true);
  Http& set_url(const std::string& url);
  Http& set_proxy(const std::string& proxy);
  Http& default_proxy(bool allow_default = true);
  Http& set_redirects(long nr);
  Http& set_timeout(long seconds);
  Http& set_post(const boost::optional<std::string>& data = boost::none);
  Http& set_post(const char* data, size_t len);
  Http& no_cache(bool no_cache = true);
  Http& set_cainfo(const std::string& pemfile);
  Http& set_connect_to(const std::string& host);

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
  boost::optional<std::string> m_post_data;
  std::string m_connect_to;

  template <typename T>
  Http& set_opt(CURLoption opt, const T& val) {
    CURLcode cc = curl_easy_setopt(m_handle.get(), opt, val);
    if (cc != CURLE_OK) throw std::runtime_error(curl_easy_strerror(cc));
    return *this;
  }
  Http& set_opt_long(CURLoption opt, long val) { return set_opt<>(opt, val); }
  Http& set_opt_ptr(CURLoption opt, void* ptr) { return set_opt<>(opt, ptr); }
};

}  // Namespace Proto
}  // Namespace NeoPG
