/* scdaemon.c  -  The GnuPG Smartcard Daemon
 * Copyright (C) 2001-2002, 2004-2005, 2007-2009 Free Software Foundation, Inc.
 * Copyright (C) 2001-2002, 2004-2005, 2007-2014 Werner Koch
 *
 * This file is part of GnuPG.
 *
 * GnuPG is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * GnuPG is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <https://www.gnu.org/licenses/>.
 */

#include <config.h>

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#ifndef HAVE_W32_SYSTEM
#include <sys/socket.h>
#include <sys/un.h>
#endif /*HAVE_W32_SYSTEM*/
#include <signal.h>
#include <unistd.h>

#define GNUPG_COMMON_NEED_AFLOCAL
#include <gcrypt.h>
#include <ksba.h>
#include "scdaemon.h"

#include <assuan.h> /* malloc hooks */

#include "../common/asshelp.h"
#include "../common/exechelp.h"
#include "../common/init.h"
#include "../common/sysutils.h"
#include "apdu.h"
#include "app-common.h"
#include "ccid-driver.h"
#include "iso7816.h"

#ifndef ENAMETOOLONG
#define ENAMETOOLONG EINVAL
#endif

enum cmd_and_opt_values {
  aNull = 0,
  oCsh = 'c',
  oQuiet = 'q',
  oSh = 's',
  oVerbose = 'v',

  oNoVerbose = 500,
  oOptions,
  oDebug,
  oDebugAll,
  oDebugLevel,
  oDebugWait,
  oDebugAllowCoreDump,
  oDebugCCIDDriver,
  oDebugAssuanLogCats,
  oNoGreeting,
  oNoOptions,
  oHomedir,
  oNoDetach,
  oNoGrab,
  oLogFile,
  oServer,
  oBatch,
  oReaderPort,
  oCardTimeout,
  oDisableCCID,
  oDisableOpenSC,
  oDisablePinpad,
  oEnablePinpadVarlen,
};

static ARGPARSE_OPTS opts[] = {
    ARGPARSE_group(301, N_("@Options:\n ")),

    ARGPARSE_s_n(oServer, "server", N_("run in server mode (foreground)")),
    ARGPARSE_s_n(oVerbose, "verbose", N_("verbose")),
    ARGPARSE_s_n(oQuiet, "quiet", N_("be somewhat more quiet")),
    ARGPARSE_s_n(oSh, "sh", N_("sh-style command output")),
    ARGPARSE_s_n(oCsh, "csh", N_("csh-style command output")),
    ARGPARSE_s_s(oOptions, "options", N_("|FILE|read options from FILE")),
    ARGPARSE_s_s(oDebug, "debug", "@"),
    ARGPARSE_s_n(oDebugAll, "debug-all", "@"),
    ARGPARSE_s_s(oDebugLevel, "debug-level",
                 N_("|LEVEL|set the debugging level to LEVEL")),
    ARGPARSE_s_i(oDebugWait, "debug-wait", "@"),
    ARGPARSE_s_n(oDebugAllowCoreDump, "debug-allow-core-dump", "@"),
    ARGPARSE_s_n(oDebugCCIDDriver, "debug-ccid-driver", "@"),
    ARGPARSE_p_u(oDebugAssuanLogCats, "debug-assuan-log-cats", "@"),
    ARGPARSE_s_n(oNoDetach, "no-detach", N_("do not detach from the console")),
    ARGPARSE_s_s(oLogFile, "log-file", N_("|FILE|write a log to FILE")),
    ARGPARSE_s_s(oReaderPort, "reader-port",
                 N_("|N|connect to reader at port N")),
    ARGPARSE_s_n(oDisableCCID, "disable-ccid",
#ifdef HAVE_LIBUSB
                 N_("do not use the internal CCID driver")
#else
                 "@"
#endif
                 /* end --disable-ccid */),
    ARGPARSE_s_u(oCardTimeout, "card-timeout",
                 N_("|N|disconnect the card after N seconds of inactivity")),

    ARGPARSE_s_n(oDisablePinpad, "disable-pinpad",
                 N_("do not use a reader's pinpad")),
    ARGPARSE_ignore(300, "disable-keypad"),

    ARGPARSE_s_n(oEnablePinpadVarlen, "enable-pinpad-varlen",
                 N_("use variable length input for pinpad")),
    ARGPARSE_s_s(oHomedir, "homedir", "@"),

    ARGPARSE_end()};

/* The list of supported debug flags.  */
static struct debug_flags_s debug_flags[] = {
    {DBG_MPI_VALUE, "mpi"},         {DBG_CRYPTO_VALUE, "crypto"},
    {DBG_MEMORY_VALUE, "memory"},   {DBG_CACHE_VALUE, "cache"},
    {DBG_MEMSTAT_VALUE, "memstat"}, {DBG_HASHING_VALUE, "hashing"},
    {DBG_IPC_VALUE, "ipc"},         {DBG_CARD_IO_VALUE, "cardio"},
    {DBG_READER_VALUE, "reader"},   {0, NULL}};

/* The timer tick used to check card removal.

   We poll every 500ms to let the user immediately know a status
   change.

   For a card reader with an interrupt endpoint, this timer is not
   used with the internal CCID driver.

   This is not too good for power saving but given that there is no
   easy way to block on card status changes it is the best we can do.
   For PC/SC we could in theory use an extra thread to wait for status
   changes.  Given that a native thread could only be used under W32
   we don't do that at all.  */
#define TIMERTICK_INTERVAL_SEC (0)
#define TIMERTICK_INTERVAL_USEC (500000)

/* Flag to indicate that a shutdown was requested. */
static int shutdown_pending;

#ifdef HAVE_W32_SYSTEM
static HANDLE the_event;
#else
/* PID to notify update of usb devices.  */
static pid_t main_thread_pid;
#endif

static char *make_libversion(const char *libname,
                             const char *(*getfnc)(const char *)) {
  const char *s;
  char *result;

  s = getfnc(NULL);
  result = (char *)xmalloc(strlen(libname) + 1 + strlen(s) + 1);
  strcpy(stpcpy(stpcpy(result, libname), " "), s);
  return result;
}

static const char *my_strusage(int level) {
  static char *ver_gcry, *ver_ksba;
  const char *p = NULL;

  switch (level) {
    case 11:
      p = "@SCDAEMON@ (@GNUPG@)";
      break;
    case 13:
      p = VERSION;
      break;
    case 19:
      p = _("Please report bugs to <@EMAIL@>.\n");
      break;

    case 1:
    case 40:
      p = _("Usage: @SCDAEMON@ [options] (-h for help)");
      break;
    case 41:
      p =
          _("Syntax: scdaemon [options] [command [args]]\n"
            "Smartcard daemon for @GNUPG@\n");
      break;

    default:
      p = NULL;
  }
  return p;
}

/* Setup the debugging.  With a LEVEL of NULL only the active debug
   flags are propagated to the subsystems.  With LEVEL set, a specific
   set of debug flags is set; thus overriding all flags already
   set. */
static void set_debug(const char *level) {
  int numok = (level && digitp(level));
  int numlvl = numok ? atoi(level) : 0;

  if (!level)
    ;
  else if (!strcmp(level, "none") || (numok && numlvl < 1))
    opt.debug = 0;
  else if (!strcmp(level, "basic") || (numok && numlvl <= 2))
    opt.debug = DBG_IPC_VALUE;
  else if (!strcmp(level, "advanced") || (numok && numlvl <= 5))
    opt.debug = DBG_IPC_VALUE;
  else if (!strcmp(level, "expert") || (numok && numlvl <= 8))
    opt.debug = (DBG_IPC_VALUE | DBG_CACHE_VALUE | DBG_CARD_IO_VALUE);
  else if (!strcmp(level, "guru") || numok) {
    opt.debug = ~0;
    /* Unless the "guru" string has been used we don't want to allow
       hashing debugging.  The rationale is that people tend to
       select the highest debug value and would then clutter their
       disk with debug files which may reveal confidential data.  */
    if (numok) opt.debug &= ~(DBG_HASHING_VALUE);
  } else {
    log_error(_("invalid debug-level '%s' given\n"), level);
    scd_exit(2);
  }

  if (opt.debug && !opt.verbose) opt.verbose = 1;
  if (opt.debug && opt.quiet) opt.quiet = 0;

  if (opt.debug & DBG_MPI_VALUE) gcry_control(GCRYCTL_SET_DEBUG_FLAGS, 2);
  if (opt.debug & DBG_CRYPTO_VALUE) gcry_control(GCRYCTL_SET_DEBUG_FLAGS, 1);
  gcry_control(GCRYCTL_SET_VERBOSITY, (int)opt.verbose);

  if (opt.debug) parse_debug_flag(NULL, &opt.debug, debug_flags);
}

static void scd_init_default_ctrl(ctrl_t ctrl) { (void)ctrl; }

static void scd_deinit_default_ctrl(ctrl_t ctrl) {
  if (!ctrl) return;
  xfree(ctrl->in_data.value);
  ctrl->in_data.value = NULL;
  ctrl->in_data.valuelen = 0;
}

int scd_main(int argc, char **argv) {
  ARGPARSE_ARGS pargs;
  int orig_argc;
  char **orig_argv;
  FILE *configfp = NULL;
  char *configname = NULL;
  const char *shell;
  unsigned int configlineno;
  int parse_debug = 0;
  const char *debug_level = NULL;
  int default_config = 1;
  int greeting = 0;
  int nogreeting = 0;
  int is_daemon = 0;
  int nodetach = 0;
  char *logfile = NULL;
  int debug_wait = 0;
  int allow_coredump = 0;
  struct assuan_malloc_hooks malloc_hooks;
  int res;

  early_system_init();
  set_strusage(my_strusage);
  gcry_control(GCRYCTL_SUSPEND_SECMEM_WARN);
  log_set_prefix("scdaemon", GPGRT_LOG_WITH_PREFIX | GPGRT_LOG_WITH_PID);

  /* Make sure that our subsystems are ready.  */
  init_common_subsystems(&argc, &argv);

  ksba_set_malloc_hooks(gcry_malloc, gcry_realloc, gcry_free);

  malloc_hooks.malloc = gcry_malloc;
  malloc_hooks.realloc = gcry_realloc;
  malloc_hooks.free = gcry_free;
  assuan_set_malloc_hooks(&malloc_hooks);
  assuan_sock_init();
  setup_libassuan_logging(&opt.debug, NULL);

  setup_libgcrypt_logging();
  gcry_control(GCRYCTL_USE_SECURE_RNDPOOL);

  disable_core_dumps();

  /* Check whether we have a config file on the commandline */
  orig_argc = argc;
  orig_argv = argv;
  pargs.argc = &argc;
  pargs.argv = &argv;
  pargs.flags = 1 | (1 << 6); /* do not remove the args, ignore version */
  while (arg_parse(&pargs, opts)) {
    if (pargs.r_opt == oDebug || pargs.r_opt == oDebugAll)
      parse_debug++;
    else if (pargs.r_opt == oOptions) { /* yes there is one, so we do not try
                                           the default one, but
                                           read the option file when it is
                                           encountered at the
                                           commandline */
      default_config = 0;
    } else if (pargs.r_opt == oNoOptions)
      default_config = 0; /* --no-options */
    else if (pargs.r_opt == oHomedir)
      gnupg_set_homedir(pargs.r.ret_str);
  }

  /* initialize the secure memory. */
  gcry_control(GCRYCTL_INIT_SECMEM, 16384, 0);

  /*
     Now we are working under our real uid
  */

  if (default_config)
    configname =
        make_filename(gnupg_homedir(), SCDAEMON_NAME EXTSEP_S "conf", NULL);

  argc = orig_argc;
  argv = orig_argv;
  pargs.argc = &argc;
  pargs.argv = &argv;
  pargs.flags = 1; /* do not remove the args */
next_pass:
  if (configname) {
    configlineno = 0;
    configfp = fopen(configname, "r");
    if (!configfp) {
      if (default_config) {
        if (parse_debug)
          log_info(_("Note: no default option file '%s'\n"), configname);
      } else {
        log_error(_("option file '%s': %s\n"), configname, strerror(errno));
        exit(2);
      }
      xfree(configname);
      configname = NULL;
    }
    if (parse_debug && configname)
      log_info(_("reading options from '%s'\n"), configname);
    default_config = 0;
  }

  while (optfile_parse(configfp, configname, &configlineno, &pargs, opts)) {
    switch (pargs.r_opt) {
      case oQuiet:
        opt.quiet = 1;
        break;
      case oVerbose:
        opt.verbose++;
        break;
      case oBatch:
        opt.batch = 1;
        break;

      case oDebug:
        if (parse_debug_flag(pargs.r.ret_str, &opt.debug, debug_flags)) {
          pargs.r_opt = ARGPARSE_INVALID_ARG;
          pargs.err = ARGPARSE_PRINT_ERROR;
        }
        break;
      case oDebugAll:
        opt.debug = ~0;
        break;
      case oDebugLevel:
        debug_level = pargs.r.ret_str;
        break;
      case oDebugWait:
        debug_wait = pargs.r.ret_int;
        break;
      case oDebugAllowCoreDump:
        enable_core_dumps();
        allow_coredump = 1;
        break;
      case oDebugCCIDDriver:
#ifdef HAVE_LIBUSB
        ccid_set_debug_level(ccid_set_debug_level(-1) + 1);
#endif /*HAVE_LIBUSB*/
        break;
      case oDebugAssuanLogCats:
        set_libassuan_log_cats(pargs.r.ret_ulong);
        break;

      case oOptions:
        /* config files may not be nested (silently ignore them) */
        if (!configfp) {
          xfree(configname);
          configname = xstrdup(pargs.r.ret_str);
          goto next_pass;
        }
        break;
      case oNoGreeting:
        nogreeting = 1;
        break;
      case oNoVerbose:
        opt.verbose = 0;
        break;
      case oNoOptions:
        break; /* no-options */
      case oHomedir:
        gnupg_set_homedir(pargs.r.ret_str);
        break;
      case oNoDetach:
        nodetach = 1;
        break;
      case oLogFile:
        logfile = pargs.r.ret_str;
        break;
      case oServer: /* Default */
        break;

      case oReaderPort:
        opt.reader_port = pargs.r.ret_str;
        break;
      case oDisableCCID:
        opt.disable_ccid = 1;
        break;
      case oDisableOpenSC:
        break;

      case oDisablePinpad:
        opt.disable_pinpad = 1;
        break;

      case oCardTimeout:
        opt.card_timeout = pargs.r.ret_ulong;
        break;

      case oEnablePinpadVarlen:
        opt.enable_pinpad_varlen = 1;
        break;

      default:
        pargs.err = configfp ? ARGPARSE_PRINT_WARNING : ARGPARSE_PRINT_ERROR;
        break;
    }
  }
  if (configfp) {
    fclose(configfp);
    configfp = NULL;
    configname = NULL;
    goto next_pass;
  }
  xfree(configname);
  configname = NULL;
  if (log_get_errorcount(0)) exit(2);
  if (nogreeting) greeting = 0;

  if (greeting) {
    es_fprintf(es_stderr, "%s %s; %s\n", strusage(11), strusage(13),
               strusage(14));
    es_fprintf(es_stderr, "%s\n", strusage(15));
  }

  /* Print a warning if an argument looks like an option.  */
  if (!opt.quiet && !(pargs.flags & ARGPARSE_FLAG_STOP_SEEN)) {
    int i;

    for (i = 0; i < argc; i++)
      if (argv[i][0] == '-' && argv[i][1] == '-')
        log_info(_("Note: '%s' is not considered an option\n"), argv[i]);
  }

  set_debug(debug_level);

  /* Now start with logging to a file if this is desired.  */
  if (logfile) {
    log_set_file(logfile);
    log_set_prefix(
        NULL, GPGRT_LOG_WITH_PREFIX | GPGRT_LOG_WITH_TIME | GPGRT_LOG_WITH_PID);
  }

  if (debug_wait) {
    log_debug("waiting for debugger - my pid is %u .....\n",
              (unsigned int)getpid());
    gnupg_sleep(debug_wait);
    log_debug("... okay\n");
  }

  {
    /* This is the simple pipe based server */
    ctrl_t ctrl;
    int fd = -1;

#ifndef HAVE_W32_SYSTEM
    {
      struct sigaction sa;

      sa.sa_handler = SIG_IGN;
      sigemptyset(&sa.sa_mask);
      sa.sa_flags = 0;
      sigaction(SIGPIPE, &sa, NULL);
    }
#endif

    /* If --debug-allow-core-dump has been given we also need to
       switch the working directory to a place where we can actually
       write. */
    if (allow_coredump) {
      if (chdir("/tmp"))
        log_debug("chdir to '/tmp' failed: %s\n", strerror(errno));
      else
        log_debug("changed working directory to '/tmp'\n");
    }

    ctrl = (ctrl_t)xtrycalloc(1, sizeof *ctrl);
    if (!ctrl) {
      log_error("error allocating connection control data: %s\n",
                strerror(errno));
      scd_exit(2);
    }

    scd_init_default_ctrl(ctrl);
    if (scd_command_handler(ctrl)) shutdown_pending = 1;

    scd_deinit_default_ctrl(ctrl);
    xfree(ctrl);
  }

  return 0;
}

void scd_exit(int rc) {
  apdu_prepare_exit();
#if 0
#warning no update_random_seed_file
  update_random_seed_file();
#endif
#if 0
  /* at this time a bit annoying */
  if (opt.debug & DBG_MEMSTAT_VALUE)
    {
      gcry_control( GCRYCTL_DUMP_MEMORY_STATS );
      gcry_control( GCRYCTL_DUMP_RANDOM_STATS );
    }
  if (opt.debug)
    gcry_control (GCRYCTL_DUMP_SECMEM_STATS );
#endif
  gcry_control(GCRYCTL_TERM_SECMEM);
  rc = rc ? rc : log_get_errorcount(0) ? 2 : 0;
  exit(rc);
}

#ifndef HAVE_W32_SYSTEM
static void handle_signal(int signo) {
  switch (signo) {
    case SIGHUP:
      log_info(
          "SIGHUP received - "
          "re-reading configuration and resetting cards\n");
      /*       reread_configuration (); */
      break;

    case SIGUSR1:
      log_info("SIGUSR1 received - printing internal information:\n");
      /* Fixme: We need to see how to integrate pth dumping into our
         logging system.  */
      /* pth_ctrl (PTH_CTRL_DUMPSTATE, log_get_stream ()); */
      app_dump_state();
      break;

    case SIGUSR2:
      log_info("SIGUSR2 received - no action defined\n");
      break;

    case SIGCONT:
      /* Nothing.  */
      break;

    case SIGTERM:
      shutdown_pending++;
      if (shutdown_pending > 2) {
        log_info("shutdown forced\n");
        log_info("%s %s stopped\n", strusage(11), strusage(13));
        scd_exit(0);
      }
      break;

    case SIGINT:
      log_info("SIGINT received - immediate shutdown\n");
      log_info("%s %s stopped\n", strusage(11), strusage(13));
      scd_exit(0);
      break;

    default:
      log_info("signal %d received - no action defined\n", signo);
  }
}
#endif /*!HAVE_W32_SYSTEM*/

void scd_kick_the_loop(void) {
  int ret;

/* Kick the select loop.  */
#ifdef HAVE_W32_SYSTEM
  ret = SetEvent(the_event);
  if (ret == 0)
    log_error("SetEvent for scd_kick_the_loop failed: %s\n", w32_strerror(-1));
#else
  ret = kill(main_thread_pid, SIGCONT);
  if (ret < 0)
    log_error("SetEvent for scd_kick_the_loop failed: %s\n",
              gpg_strerror(gpg_error_from_syserror()));
#endif
}
