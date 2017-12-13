/* Tests for stream functions
   Copyright 2017 The NeoPG developers

   NeoPG is released under the Simplified BSD License (see license.txt)
*/

#include <neopg/proto/uri.h>
#include "gtest/gtest.h"

using namespace NeoPG;

namespace NeoPG {

TEST(NeoPGTest, proto_uri_test) {
  {
    Proto::URI uri;
    std::string input;
    EXPECT_EQ(uri.str(), "");

    input = "http://www.example.org";
    uri.set_uri(input);
    EXPECT_EQ(uri.scheme, "http");
    EXPECT_EQ(uri.authority, "www.example.org");
    EXPECT_EQ(uri.userinfo, "");
    EXPECT_EQ(uri.host, "www.example.org");
    EXPECT_EQ(uri.port, "");
    EXPECT_EQ(uri.path, "");
    EXPECT_EQ(uri.query, "");
    EXPECT_EQ(uri.fragment, "");
    EXPECT_EQ(uri.str(), input);

    input = "https://www.example.org:10080/index.html";
    uri.set_uri(input);
    EXPECT_EQ(uri.scheme, "https");
    EXPECT_EQ(uri.authority, "www.example.org:10080");
    EXPECT_EQ(uri.userinfo, "");
    EXPECT_EQ(uri.host, "www.example.org");
    EXPECT_EQ(uri.port, "10080");
    EXPECT_EQ(uri.path, "/index.html");
    EXPECT_EQ(uri.query, "");
    EXPECT_EQ(uri.fragment, "");
    EXPECT_EQ(uri.str(), input);

    input = "http://nobody@www.example.org/?name=foo#chapter1";
    uri.set_uri(input);
    EXPECT_EQ(uri.scheme, "http");
    EXPECT_EQ(uri.authority, "nobody@www.example.org");
    EXPECT_EQ(uri.userinfo, "nobody");
    EXPECT_EQ(uri.host, "www.example.org");
    EXPECT_EQ(uri.port, "");
    EXPECT_EQ(uri.path, "/");
    EXPECT_EQ(uri.query, "name=foo");
    EXPECT_EQ(uri.fragment, "chapter1");
    EXPECT_EQ(uri.str(), input);
  }
}
}
