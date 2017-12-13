/* HTTP Protocol support
   Copyright 2017 The NeoPG developers

   NeoPG is released under the Simplified BSD License (see license.txt)
*/

#include <neopg/proto/uri.h>
#include <tao/pegtl/contrib/uri.hpp>
#include <tao/pegtl/parse.hpp>

#include <iostream>

namespace NeoPG {
namespace Proto {

namespace pegtl = tao::TAOCPP_PEGTL_NAMESPACE;

namespace uri {
struct grammar : pegtl::must<pegtl::uri::URI> {};

/* The pointer to class data member allows to use the right function
   signature for apply() but also access arbitrary string members
   inside the class.  If you come from C, think "offsetof()".  */
template <std::string URI::*Field>
struct bind {
  template <typename Input>
  static void apply(const Input& in, URI& uri, std::string& tmp) {
    uri.*Field = in.string();
  }
};

template <typename Rule>
struct action : tao::pegtl::nothing<Rule> {};

template <>
struct action<pegtl::uri::scheme> : bind<&URI::scheme> {};

template <>
struct action<pegtl::uri::authority> : bind<&URI::authority> {};

template <>
struct action<pegtl::uri::userinfo> {
  template <typename Input>
  static void apply(const Input& in, URI& uri, std::string& tmp) {
    /* We might backtrack.  */
    tmp = in.string();
  }
};

/* FIXME: Change this with the next pegtl release, see
   https://github.com/taocpp/PEGTL/issues/79.  */
template <>
struct action<pegtl::one<'@'>> {
  template <typename Input>
  static void apply(const Input& in, URI& uri, std::string& tmp) {
    uri.userinfo = tmp;
  }
};

template <>
struct action<pegtl::uri::host> : bind<&URI::host> {};

template <>
struct action<pegtl::uri::port> : bind<&URI::port> {};

template <>
struct action<pegtl::uri::path_abempty> : bind<&URI::path> {};

template <>
struct action<pegtl::uri::path_rootless> : bind<&URI::path> {};

template <>
struct action<pegtl::uri::path_absolute> : bind<&URI::path> {};

template <>
struct action<pegtl::uri::path_empty> : bind<&URI::path> {};

template <>
struct action<pegtl::uri::query> : bind<&URI::query> {};

template <>
struct action<pegtl::uri::fragment> : bind<&URI::fragment> {};
};

URI& URI::clear() {
  scheme.clear();
  authority.clear();
  userinfo.clear();
  host.clear();
  port.clear();
  path.clear();
  query.clear();
  fragment.clear();
  return *this;
}

URI& URI::set_uri(const std::string& uri) {
  clear();

  pegtl::memory_input<> input(uri.data(), uri.size(), "uri");
  std::string tmp;
  pegtl::parse<uri::grammar, uri::action>(input, *this, tmp);

  return *this;
}

std::string URI::str() {
  std::string uri;
  if (scheme.size()) uri += scheme + ":";
  if (userinfo.size() || host.size() || port.size()) {
    uri += "//";
    if (userinfo.size()) uri += userinfo + "@";
    if (host.size()) uri += host;
    if (port.size()) uri += ":" + port;
  }
  if (path.size()) uri += path;
  if (query.size()) uri += "?" + query;
  if (fragment.size()) uri += "#" + fragment;
  return uri;
}

}  // Namespace Proto
}  // Namespace NeoPG
