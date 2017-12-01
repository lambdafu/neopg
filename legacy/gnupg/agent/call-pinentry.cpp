/* call-pinentry.c - Spawn the pinentry to query stuff from the user
 * Copyright (C) 2001, 2002, 2004, 2007, 2008,
 *               2010  Free Software Foundation, Inc.
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

#include <assert.h>
#include <config.h>
#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#ifndef HAVE_W32_SYSTEM
#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#endif

#include <assuan.h>
#include "../common/sysutils.h"
#include "agent.h"

#ifdef _POSIX_OPEN_MAX
#define MAX_OPEN_FDS _POSIX_OPEN_MAX
#else
#define MAX_OPEN_FDS 20
#endif

/* Because access to the pinentry must be serialized (it is and shall
   be a global mutually exclusive dialog) we better timeout pending
   requests after some time.  1 minute seem to be a reasonable
   time. */
#define LOCK_TIMEOUT (1 * 60)

/* The assuan context of the current pinentry. */
static assuan_context_t entry_ctx;

/* A list of features of the current pinentry.  */
static struct {
  /* The Pinentry support RS+US tabbing.  This means that a RS (0x1e)
   * starts a new tabbing block in which a US (0x1f) followed by a
   * colon marks a colon.  A pinentry can use this to pretty print
   * name value pairs.  */
  unsigned int tabbing : 1;
} entry_features;

/* A flag used in communication between the popup working thread and
   its stop function. */
static int popup_finished;

/* Data to be passed to our callbacks, */
struct entry_parm_s {
  int lines;
  size_t size;
  unsigned char *buffer;
};

/* This function may be called to print information pertaining to the
   current state of this module to the log. */
void agent_query_dump_state(void) {
  log_info("agent_query_dump_state: entry_ctx=%p pid=%ld\n", entry_ctx,
           (long)assuan_get_pid(entry_ctx));
}

/* Called to make sure that a popup window owned by the current
   connection gets closed. */
void agent_reset_query(ctrl_t ctrl) {}

/* Call the Entry and ask for the PIN.  We do check for a valid PIN
   number here and repeat it as long as we have invalid formed
   numbers.  KEYINFO and CACHE_MODE are used to tell pinentry something
   about the key. */
gpg_error_t agent_askpin(ctrl_t ctrl, const char *desc_text,
                         const char *prompt_text, const char *initial_errtext,
                         struct pin_entry_info_s *pininfo, const char *keyinfo,
                         cache_mode_t cache_mode) {
  gpg_error_t rc;
  if (opt.batch) return 0; /* fixme: we should return BAD PIN */

  {
    unsigned char *passphrase;
    size_t size;

    *pininfo->pin = 0; /* Reset the PIN. */
    rc = pinentry_loopback(ctrl, "PASSPHRASE", &passphrase, &size,
                           pininfo->max_length - 1);
    if (rc) return rc;

    memcpy(&pininfo->pin, passphrase, size);
    xfree(passphrase);
    pininfo->pin[size] = 0;
    if (pininfo->check_cb) {
      /* More checks by utilizing the optional callback. */
      pininfo->cb_errtext = NULL;
      rc = pininfo->check_cb(pininfo);
    }
    return rc;
  }
}

/* Ask for the passphrase using the supplied arguments.  The returned
   passphrase needs to be freed by the caller. */
int agent_get_passphrase(ctrl_t ctrl, char **retpass, const char *desc,
                         const char *prompt, const char *errtext,
                         const char *keyinfo, cache_mode_t cache_mode) {
  *retpass = NULL;
  if (opt.batch) return GPG_ERR_BAD_PASSPHRASE;

  {
    size_t size;

    return pinentry_loopback(ctrl, "PASSPHRASE", (unsigned char **)retpass,
                             &size, MAX_PASSPHRASE_LEN);
  }
}

/* Pop up the PIN-entry, display the text and the prompt and ask the
   user to confirm this.  We return 0 for success, ie. the user
   confirmed it, GPG_ERR_NOT_CONFIRMED for what the text says or an
   other error.  If WITH_CANCEL it true an extra cancel button is
   displayed to allow the user to easily return a GPG_ERR_CANCELED.
   if the Pinentry does not support this, the user can still cancel by
   closing the Pinentry window.  */
int agent_get_confirmation(ctrl_t ctrl, const char *desc, const char *ok,
                           const char *notok, int with_cancel) {
  return GPG_ERR_NO_PIN_ENTRY;
}

/* Pop up the PINentry, display the text DESC and a button with the
   text OK_BTN (which may be NULL to use the default of "OK") and wait
   for the user to hit this button.  The return value is not
   relevant.  */
int agent_show_message(ctrl_t ctrl, const char *desc, const char *ok_btn) {
  return GPG_ERR_CANCELED;
}

/* Pop up a message window similar to the confirm one but keep it open
   until agent_popup_message_stop has been called.  It is crucial for
   the caller to make sure that the stop function gets called as soon
   as the message is not anymore required because the message is
   system modal and all other attempts to use the pinentry will fail
   (after a timeout). */
int agent_popup_message_start(ctrl_t ctrl, const char *desc,
                              const char *ok_btn) {
  return GPG_ERR_CANCELED;
}

/* Close a popup window. */
void agent_popup_message_stop(ctrl_t ctrl) {}

int agent_clear_passphrase(ctrl_t ctrl, const char *keyinfo,
                           cache_mode_t cache_mode) {
  return 0;
}
