/* asshelp.c - Helper functions for Assuan
 * Copyright (C) 2002, 2004, 2007, 2009, 2010 Free Software Foundation, Inc.
 *
 * This file is part of GnuPG.
 *
 * This file is free software; you can redistribute it and/or modify
 * it under the terms of either
 *
 *   - the GNU Lesser General Public License as published by the Free
 *     Software Foundation; either version 3 of the License, or (at
 *     your option) any later version.
 *
 * or
 *
 *   - the GNU General Public License as published by the Free
 *     Software Foundation; either version 2 of the License, or (at
 *     your option) any later version.
 *
 * or both in parallel, as here.
 *
 * This file is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <https://www.gnu.org/licenses/>.
 */

#include <config.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#ifdef HAVE_LOCALE_H
#include <locale.h>
#endif

#include "asshelp.h"
#include "exechelp.h"
#include "membuf.h"
#include "status.h"
#include "sysutils.h"
#include "util.h"

/* The type we use for lock_agent_spawning.  */
#ifdef HAVE_W32_SYSTEM
#define lock_spawn_t HANDLE
#else
#define lock_spawn_t dotlock_t
#endif

/* The time we wait until the agent or the dirmngr are ready for
   operation after we started them before giving up.  */
#define SECS_TO_WAIT_FOR_AGENT 5
#define SECS_TO_WAIT_FOR_DIRMNGR 5

/* A bitfield that specifies the assuan categories to log.  This is
   identical to the default log handler of libassuan.  We need to do
   it ourselves because we use a custom log handler and want to use
   the same assuan variables to select the categories to log. */
static int log_cats;
#define TEST_LOG_CAT(x) (!!(log_cats & (1 << (x - 1))))

/* The assuan log monitor used to temporary inhibit log messages from
 * assuan.  */
static int (*my_log_monitor)(assuan_context_t ctx, unsigned int cat,
                             const char *msg);

static int my_libassuan_log_handler(assuan_context_t ctx, void *hook,
                                    unsigned int cat, const char *msg) {
  unsigned int dbgval;

  if (!TEST_LOG_CAT(cat)) return 0;

  dbgval = hook ? *(unsigned int *)hook : 0;
  if (!(dbgval & 1024)) return 0; /* Assuan debugging is not enabled.  */

  if (ctx && my_log_monitor && !my_log_monitor(ctx, cat, msg))
    return 0; /* Temporary disabled.  */

  if (msg) log_string(GPGRT_LOG_DEBUG, msg);

  return 1;
}

/* Setup libassuan to use our own logging functions.  Should be used
   early at startup.  */
void setup_libassuan_logging(unsigned int *debug_var_address,
                             int (*log_monitor)(assuan_context_t ctx,
                                                unsigned int cat,
                                                const char *msg)) {
  char *flagstr;

  flagstr = getenv("ASSUAN_DEBUG");
  if (flagstr)
    log_cats = atoi(flagstr);
  else /* Default to log the control channel.  */
    log_cats = (1 << (ASSUAN_LOG_CONTROL - 1));
  my_log_monitor = log_monitor;
  assuan_set_log_cb(my_libassuan_log_handler, debug_var_address);
}

/* Change the Libassuan log categories to those given by NEWCATS.
   NEWCATS is 0 the default category of ASSUAN_LOG_CONTROL is
   selected.  Note, that setup_libassuan_logging overrides the values
   given here.  */
void set_libassuan_log_cats(unsigned int newcats) {
  if (newcats)
    log_cats = newcats;
  else /* Default to log the control channel.  */
    log_cats = (1 << (ASSUAN_LOG_CONTROL - 1));
}

static gpg_error_t send_one_option(assuan_context_t ctx, const char *name,
                                   const char *value, int use_putenv) {
  gpg_error_t err;
  char *optstr;

  if (!value || !*value)
    err = 0; /* Avoid sending empty strings.  */
  else if (asprintf(&optstr, "OPTION %s%s=%s", use_putenv ? "putenv=" : "",
                    name, value) < 0)
    err = gpg_error_from_syserror();
  else {
    err = assuan_transact(ctx, optstr, NULL, NULL, NULL, NULL, NULL, NULL);
    xfree(optstr);
  }

  return err;
}

/* Send the assuan commands pertaining to the pinentry environment.  The
   OPT_* arguments are optional and may be used to override the
   defaults taken from the current locale. */
gpg_error_t send_pinentry_environment(assuan_context_t ctx,
                                      const char *opt_lc_ctype,
                                      const char *opt_lc_messages)

{
  gpg_error_t err = 0;
#if defined(HAVE_SETLOCALE)
  char *old_lc = NULL;
#endif
  char *dft_lc = NULL;
  const char *name, *assname, *value;
  int is_default;

/* Send the value for LC_CTYPE.  */
#if defined(HAVE_SETLOCALE) && defined(LC_CTYPE)
  old_lc = setlocale(LC_CTYPE, NULL);
  if (old_lc) {
    old_lc = xtrystrdup(old_lc);
    if (!old_lc) return gpg_error_from_syserror();
  }
  dft_lc = setlocale(LC_CTYPE, "");
#endif
  if (opt_lc_ctype) {
    err = send_one_option(ctx, "lc-ctype", opt_lc_ctype, 0);
  }
#if defined(HAVE_SETLOCALE) && defined(LC_CTYPE)
  if (old_lc) {
    setlocale(LC_CTYPE, old_lc);
    xfree(old_lc);
  }
#endif
  if (err) return err;

/* Send the value for LC_MESSAGES.  */
#if defined(HAVE_SETLOCALE) && defined(LC_MESSAGES)
  old_lc = setlocale(LC_MESSAGES, NULL);
  if (old_lc) {
    old_lc = xtrystrdup(old_lc);
    if (!old_lc) return gpg_error_from_syserror();
  }
  dft_lc = setlocale(LC_MESSAGES, "");
#endif
  if (opt_lc_messages) {
    err = send_one_option(ctx, "lc-messages", opt_lc_messages, 0);
  }
#if defined(HAVE_SETLOCALE) && defined(LC_MESSAGES)
  if (old_lc) {
    setlocale(LC_MESSAGES, old_lc);
    xfree(old_lc);
  }
#endif
  if (err) return err;

  return 0;
}

extern char *neopg_program;

/* Handle the server's initial greeting.  Returns a new assuan context
   at R_CTX or an error code. */
gpg_error_t start_new_gpg_agent(assuan_context_t *r_ctx,
                                const char *opt_lc_ctype,
                                const char *opt_lc_messages, int verbose,
                                int debug) {
  gpg_error_t err;
  assuan_context_t ctx;
  const char *argv[6];

  *r_ctx = NULL;

  err = assuan_new(&ctx);
  if (err) {
    log_error("error allocating assuan context: %s\n", gpg_strerror(err));
    return err;
  }

  {
    char *abs_homedir;
    int i;

    if (verbose) log_info(_("starting agent '%s'\n"), neopg_program);

    /* We better pass an absolute home directory to the agent just in
     case gpg-agent does not convert the passed name to an absolute
     one (which it should do).  */
    abs_homedir = make_absfilename_try(gnupg_homedir(), NULL);
    if (!abs_homedir) {
      gpg_error_t tmperr = gpg_error_from_syserror();
      log_error("error building filename: %s\n", gpg_strerror(tmperr));
      assuan_release(ctx);
      return tmperr;
    }

    i = 0;
    argv[i++] = neopg_program;
    argv[i++] = "agent";
    argv[i++] = "--homedir";
    argv[i++] = abs_homedir;
    argv[i++] = "--server";
    argv[i++] = NULL;

    err = assuan_pipe_connect(
        ctx, neopg_program, argv, NULL, NULL, NULL,
        ASSUAN_PIPE_CONNECT_FDPASSING | ASSUAN_PIPE_CONNECT_DETACHED);
    if (err) {
      gpg_error_t tmperr = gpg_error_from_syserror();
      log_error("error starting agent: %s\n", gpg_strerror(tmperr));
      assuan_release(ctx);
      xfree(abs_homedir);
      return tmperr;
    }

    xfree(abs_homedir);
  }

  if (debug) log_debug("connection to agent established\n");

  err = assuan_transact(ctx, "RESET", NULL, NULL, NULL, NULL, NULL, NULL);
  if (!err) {
    err = send_pinentry_environment(ctx, opt_lc_ctype, opt_lc_messages);
    if (err == GPG_ERR_FORBIDDEN) {
      /* Check whether we are in restricted mode.  */
      if (!assuan_transact(ctx, "GETINFO restricted", NULL, NULL, NULL, NULL,
                           NULL, NULL)) {
        if (verbose) log_info(_("connection to agent is in restricted mode\n"));
        err = 0;
      }
    }
  }
  if (err) {
    assuan_release(ctx);
    return err;
  }

  *r_ctx = ctx;
  return 0;
}

/* Returns a new assuan context at R_CTX or an error code. */
gpg_error_t start_new_dirmngr(assuan_context_t *r_ctx, int verbose, int debug) {
  gpg_error_t err;
  assuan_context_t ctx;

  *r_ctx = NULL;

  err = assuan_new(&ctx);
  if (err) {
    log_error("error allocating assuan context: %s\n", gpg_strerror(err));
    return err;
  }

  {
    lock_spawn_t lock;
    const char *argv[6];
    char *abs_homedir;
    int i;

    if (verbose) log_info(_("starting dirmngr '%s'\n"), neopg_program);

    abs_homedir = make_absfilename(gnupg_homedir(), NULL);
    if (!abs_homedir) {
      gpg_error_t tmperr = gpg_error_from_syserror();
      log_error("error building filename: %s\n", gpg_strerror(tmperr));
      assuan_release(ctx);
      return tmperr;
    }

    i = 0;
    argv[i++] = neopg_program;
    argv[i++] = "dirmngr";
    argv[i++] = "--homedir";
    argv[i++] = abs_homedir;
    argv[i++] = "--server";
    argv[i++] = NULL;

    err = assuan_pipe_connect(
        ctx, neopg_program, argv, NULL, NULL, NULL,
        ASSUAN_PIPE_CONNECT_FDPASSING | ASSUAN_PIPE_CONNECT_DETACHED);
    if (err) {
      gpg_error_t tmperr = gpg_error_from_syserror();
      log_error("error starting agent: %s\n", gpg_strerror(tmperr));
      assuan_release(ctx);
      xfree(abs_homedir);
      return tmperr;
    }

    xfree(abs_homedir);
  }

  if (debug) log_debug("connection to the dirmngr established\n");

  *r_ctx = ctx;
  return 0;
}

/* Return the version of a server using "GETINFO version".  On success
   0 is returned and R_VERSION receives a malloced string with the
   version which must be freed by the caller.  On error NULL is stored
   at R_VERSION and an error code returned.  Mode is in general 0 but
   certain values may be used to modify the used version command:

      MODE == 0 = Use "GETINFO version"
      MODE == 2 - Use "SCD GETINFO version"
 */
gpg_error_t get_assuan_server_version(assuan_context_t ctx, int mode,
                                      char **r_version) {
  gpg_error_t err;
  membuf_t data;

  init_membuf(&data, 64);
  err = assuan_transact(ctx,
                        mode == 2 ? "SCD GETINFO version"
                                  /**/
                                  : "GETINFO version",
                        put_membuf_cb, &data, NULL, NULL, NULL, NULL);
  if (err) {
    xfree(get_membuf(&data, NULL));
    *r_version = NULL;
  } else {
    put_membuf(&data, "", 1);
    *r_version = (char *)get_membuf(&data, NULL);
    if (!*r_version) err = gpg_error_from_syserror();
  }
  return err;
}
