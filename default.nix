let
   pkgs = import <nixpkgs> {};
in pkgs.stdenv.mkDerivation rec {
  name = "neopg-env";
  buildInputs = with pkgs; [ pkgconfig cmake gtest gcc boost sqlite botan2 zlib bzip2 gnutls libusb doxygen pythonPackages.gcovr libiconv curl ];
}
