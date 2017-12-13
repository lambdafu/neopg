/* NeoPG
   Copyright 2017 The NeoPG developers

   NeoPG is released under the Simplified BSD License (see license.txt)
*/

#include <iostream>

#include <CLI11.hpp>

#include <boost/format.hpp>
#include <boost/locale.hpp>

#include <curl/curl.h>

//#define _ boost::locale::translate
#define _ boost::locale::gettext

static void setup_locale() {
  boost::locale::generator gen;
  /* FIXME: Maybe use custom filesystem to include all mo files in the
     binary (for portable
     apps).
     http://www.boost.org/doc/libs/1_65_0/libs/locale/doc/html/messages_formatting.html#custom_file_system_support
     */
  gen.add_messages_path(CMAKE_INSTALL_PREFIX "/share/locale");
  gen.add_messages_domain("neopg");
  std::locale::global(gen(""));
  std::cout.imbue(std::locale());
}

#include <neopg/cli/armor_command.h>
#include <neopg/cli/cat_command.h>
#include <neopg/cli/command.h>
#include <neopg/cli/compress_command.h>
#include <neopg/cli/hash_command.h>
#include <neopg/cli/packet_command.h>
#include <neopg/cli/random_command.h>
#include <neopg/cli/version_command.h>

using namespace NeoPG::CLI;

int gpg_main(int argc, char** argv);
int agent_main(int argc, char** argv);
int dirmngr_main(int argc, char** argv);
int dirmngr_client_main(int argc, char** argv);
int gpgsm_main(int argc, char** argv);
int scd_main(int argc, char** argv);

char* neopg_program;

#if 0
struct openpgp : cli::command<openpgp>
{
    static const char* help()
    {
        return "Invoke openpgp";
    }

    void run()
    {
        openpgp_args.insert(openpgp_args.begin(), std::string("openpgp"));
        int argc = openpgp_args.size();
        std::vector<char*> argv;
        for(auto&& value:openpgp_args) argv.push_back((char*)value.data());

	std::string integer;
	std::string id;
	std::string body;

	tao::neopg_pegtl::argv_input<> in( argv.data(), 1 );
	// tao::neopg_pegtl::parse< NeoPG::grammar, NeoPG::action >( in, integer );
	// std::cout << "Parse result: " << integer << std::endl;
	tao::neopg_pegtl::parse< NeoPG::grammar, NeoPG::action >( in, id, body );
	std::cout << "long literal id was: " << id << std::endl;
	std::cout << "long literal body was: " << body << std::endl;

    }
};
#endif

#define GPGRT_ATTR_SENTINEL(a)
#include "../legacy/gnupg/common/stringhelp.h"

#ifdef WIN32
#include <io.h>
#endif

int main(int argc, char* argv[]) {
#ifdef _WIN32
  setmode(fileno(stdin), O_BINARY);
  setmode(fileno(stdout), O_BINARY);
#endif

  /* FIXME: This has to move into a neopg_init function.  We can't
     even use a global static constructor, because those are called
     from DllMain on Windows, and that's not allowed.  :( */
  if (curl_global_init(CURL_GLOBAL_ALL)) {
    std::cerr << "Failed to initialize CURL!\n";
    return 1;
  }

  /* Initialize translations.  */
  setup_locale();

  /* This is also used to invoke ourself.  */
  neopg_program = make_absfilename(argv[0], NULL);

  const std::vector<std::string> args(argv + 1, argv + argc);

  CLI::App app{_("NeoPG implements the OpenPGP standard.")};

  /* Translators, please add a second line saying "Report translation bugs to
   <...>" with the address for translation bugs (typically your translation
   team's web or email address).  */
  app.set_footer((boost::format(_("Report bugs to %s")) %
                  "https://github.com/das-labor/neopg")
                     .str());
  // app.require_subcommand(1);
  app.set_help_flag("--help", _("display help and exit"));
  app.add_subcommand("help", _("display help and exit"))
      ->group("")
      ->set_help_flag();
  bool oVersion = false;
  app.add_flag("--version", oVersion, _("display version and exit"));
  VersionCommand cmd_version(app, "version", _("display version and exit"));

  app.set_callback([&oVersion, &cmd_version, &app]() {
    if (oVersion) {
      cmd_version.run();
      throw CLI::Success();
    } else if (app.get_subcommands().empty() || app.got_subcommand("help")) {
      // Necessary to not get the help output of the help subcommand.
      app.reset();
      throw CLI::CallForHelp();
    }
  });

  std::string legacy_group = "command to execute (GnuPG-compatible)";
  LegacyCommand cmd_gpg2(app, gpg_main, "gpg2", "invoke gpg2", legacy_group);
  LegacyCommand cmd_gpgsm(app, gpgsm_main, "gpgsm", "invoke gpgsm",
                          legacy_group);
  LegacyCommand cmd_agent(app, agent_main, "agent", "invoke agent",
                          legacy_group);
  LegacyCommand cmd_scd(app, scd_main, "scd", "invoke scd", legacy_group);
  LegacyCommand cmd_dirmngr(app, dirmngr_main, "dirmngr", "invoke dirmngr",
                            legacy_group);
  LegacyCommand cmd_dirmngr_client(app, dirmngr_client_main, "dirmngr-client",
                                   "invoke dirmngr-client", legacy_group);

  std::string tools_group = "tools (for experts)";
  PacketCommand cmd_packet(app, "packet", "read and write OpenPGP packets",
                           tools_group);
  RandomCommand cmd_random(app, "random", "output random bytes", tools_group);
  HashCommand cmd_hash(app, "hash", "calculate hash function", tools_group);
  CompressCommand cmd_compress(app, "compress", "compress and decompress data",
                               tools_group);
  ArmorCommand cmd_armor(app, "armor", "ASCII-encode and decode binary data",
                         tools_group);
  CatCommand cmd_cat(app, "cat", "the beginning of a new Unix system",
                     tools_group);

  CLI11_PARSE(app, argc, argv);
  if (oVersion) cmd_version.run();

  return 0;
}
