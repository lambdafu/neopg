/* HTTP Protocol support
   Copyright 2017 The NeoPG developers

   NeoPG is released under the Simplified BSD License (see license.txt)
*/

#include <neopg/proto/http.h>

#include <iostream>

namespace NeoPG {
namespace Proto {

Http::Http() : m_handle(curl_easy_init(), curl_easy_cleanup) {
  if (m_handle.get() == nullptr) throw std::bad_alloc();

  set_opt_long(CURLOPT_NOSIGNAL, 1);
  set_redirects(MAX_REDIRECTS_DEFAULT);
}

Http& Http::forbid_reuse(bool no_reuse) {
  return set_opt_long(CURLOPT_FORBID_REUSE, no_reuse ? 1 : 0);
}

Http& Http::set_url(const std::string& url) {
  URI uri(url);
  if (uri.scheme == "https")
    set_opt_long(CURLOPT_REDIR_PROTOCOLS, CURLPROTO_HTTPS);
  else if (uri.scheme == "http")
    set_opt_long(CURLOPT_REDIR_PROTOCOLS, CURLPROTO_HTTP | CURLPROTO_HTTPS);
  else {
    throw std::runtime_error("unsupported protocol");
  }

  /* Would be nice to have a URI check.  */
  return set_opt_ptr(CURLOPT_URL, (void*)url.c_str());
}

Http& Http::set_proxy(const std::string& proxy) {
  return set_opt_ptr(CURLOPT_PROXY, (void*)proxy.c_str());
}

Http& Http::default_proxy(bool allow_default) {
  return set_opt_ptr(CURLOPT_PROXY, allow_default ? nullptr : (void*)"");
}

Http& Http::set_redirects(long nr) {
  if (nr == 0)
    set_opt_long(CURLOPT_FOLLOWLOCATION, 0);
  else {
    set_opt_long(CURLOPT_MAXREDIRS, nr);
    set_opt_long(CURLOPT_FOLLOWLOCATION, 1);
  }
  return *this;
}

Http& Http::set_timeout(long seconds) {
  return set_opt_long(CURLOPT_TIMEOUT, seconds);
}

Http& Http::set_post(const boost::optional<std::string>& data) {
  m_post_data = data;
  if (m_post_data) {
    set_opt_ptr(CURLOPT_POSTFIELDS, (void*)m_post_data->data());
    set_opt_long(CURLOPT_POSTFIELDSIZE, m_post_data->size());
  } else {
    set_opt_ptr(CURLOPT_POSTFIELDS, nullptr);
    set_opt_ptr(CURLOPT_POSTFIELDSIZE, 0);
    set_opt_long(CURLOPT_HTTPGET, 1L);
  }
  return *this;
}

Http& Http::set_post(const char* data, size_t len) {
  if (data == nullptr || len == 0)
    set_post(boost::none);
  else
    set_post(std::string(data, len));
  return *this;
}

Http& Http::no_cache(bool no_cache) {
  if (no_cache) {
    m_header["Pragma"] = "no-cache";
    m_header["Cache-Control"] = "no-cache";
  } else {
    m_header.erase("Pragma");
    m_header.erase("Cache-Control");
  }
  return *this;
}

Http& Http::set_cainfo(const std::string& pemfile) {
  return set_opt_ptr(CURLOPT_CAINFO, (void*)pemfile.c_str());
}

Http& Http::set_ipresolve(Resolve which) {
  return set_opt_long(CURLOPT_IPRESOLVE, (long)which);
}

Http& Http::set_connect_to(const std::string& connect_to) {
  m_connect_to = connect_to;
  if (m_connect_to.find(":") == std::string::npos) m_connect_to += ":";
  return *this;
}

/* Must be an unbound function, because it is used as C callback.  */
static size_t write_fnc(void* buffer, size_t size, size_t nmemb, void* userp) {
  std::string* response = (std::string*)userp;
  size_t amount = size * nmemb;  // Overflow?
  response->append((char*)buffer, amount);
  return amount;
}

std::string Http::fetch() {
  std::string response;
  char last_error[CURL_ERROR_SIZE] = {'\0'};
  std::unique_ptr<struct curl_slist, void (*)(struct curl_slist*)> headers{
      nullptr, curl_slist_free_all};
  std::unique_ptr<struct curl_slist, void (*)(struct curl_slist*)> connect_to{
      nullptr, curl_slist_free_all};

  set_opt_ptr(CURLOPT_WRITEFUNCTION, (void*)write_fnc);
  set_opt_ptr(CURLOPT_WRITEDATA, (void*)&response);
  // FIXME: Proxy, IP resolve, header, post, cainfo, http_code?
  set_opt_ptr(CURLOPT_ERRORBUFFER, last_error);

  for (auto& item : m_header) {
    std::string header = item.first;
    header += ": " + item.second;
    /* A bit odd: curl_slist_append also does initialization.  The return
     * value is stable after first call. */
    struct curl_slist* ptr = curl_slist_append(headers.get(), header.c_str());
    if (!ptr)
      throw std::bad_alloc();
    else if (!headers.get())
      headers.reset(ptr);
  }
  set_opt_ptr(CURLOPT_HTTPHEADER, (void*)headers.get());

  if (m_connect_to.size()) {
    std::string arg;
    arg += "::" + m_connect_to;
    struct curl_slist* ptr = curl_slist_append(nullptr, arg.c_str());
    if (!ptr)
      throw std::bad_alloc();
    else
      connect_to.reset(ptr);
    set_opt_ptr(CURLOPT_CONNECT_TO, (void*)connect_to.get());
  }

  CURLcode result = curl_easy_perform(m_handle.get());
  if (result != CURLE_OK) throw std::runtime_error(last_error);

  m_last_error = last_error;

  long http_code;
  curl_easy_getinfo(m_handle.get(), CURLINFO_RESPONSE_CODE, &http_code);
  std::string reason;
  reason += "HTTP " + std::to_string(http_code);
  if (http_code != 200) throw std::runtime_error(reason);

  // Clear post data so it is never reused accidentially.
  set_post();
  m_connect_to = "";
  /* This is probably too simplicistic.  */
  m_header.clear();
  return response;
}

}  // Namespace Proto
}  // Namespace NeoPG
