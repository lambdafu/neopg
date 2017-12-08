@title[NeoPG]

# NeoPG

#### A multiversal crypto-engine.

---

@title[An OpenPGP implementation]

* Compatible with gpg/2
* All the good and bad stuff of OpenPGP
* easy to use the good stuff
* hard to use the bad stuff

---

@title[New Command Line Interface]

* git-style subcommands (and subcommands of subcommands)
* colors!
* gpg2-compatible legacy interface
* single binary (portable apps friendly)
* no system-wide configuration, no daemons, no complicated packaging
* kitchen sink included (hash, compress, armor, random)

---

@title[Collaboration]

* 2-clause BSD license (nobody has time for license wars)
* hosted on GitHub
* pull requests welcome (no contributor agreement needed)

---

@title[Coding like it's the early 2000's!]

* C++11 (gcc >= 4.8, clang, MSVC)
* Heavy use of STL for memory management
* Boost to fill the gaps in STL and abstract platform specific code
* Botan for cryptographic primitives and higher level protocol support

---

@title[Finally, a library!]

* libneopg is the "library for GPG" that never was
* easy high-level interface
* transparent in depth
* all policy decisions replaceable (trust interface, passphrase lookup, etc)
* libgpgme-compatible legacy interface

---

@title[Focus on Code Quality]

* Unit-testing (easy because of libneopg)
* Continuous integration on Linux, MacOS and Windows (Travis, AppVoyeur)
* Fuzzing
* Static code analysis
* Linting, Source Code Formatting (clang-format)

---

@title[Efficiency]

* New key database based on SQLite3.
* Works with large key databases (Debian keyring).
* Efficient programming with high-level abstractions and well-organized components.

---

@title[Hardware-based security]

* Smartcard support out of the box (OpenPGP Card, Gnuk, Yubikey?)
* based on PCSCD (Linux+MacOS, cooperates with other apps)

---
@title[Beyond the web of trust]

* New trust models easy to write.
* keybase.io integration
* Central keyserver that actually verifies email addresses.
* neopg tweet @lambdafu "Do you know yolo-encryption?"

