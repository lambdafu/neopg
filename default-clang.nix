let
   pkgs = import <nixpkgs> {};
in pkgs.clangStdenv.mkDerivation rec {
  name = "neopg-env";
  buildInputs = with pkgs; [ pkgconfig llvm cmake gtest clang boost sqlite botan2 zlib bzip2 gnutls libusb doxygen pythonPackages.gcovr libiconv curl ];
}
