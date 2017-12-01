/* apdu.c - ISO 7816 APDU functions and low level I/O
 * Copyright (C) 2003, 2004, 2008, 2009, 2010,
 *               2011 Free Software Foundation, Inc.
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

#include <mutex>

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

/* If requested include the definitions for the remote APDU protocol
   code. */
#ifdef USE_G10CODE_RAPDU
#include "rapdu.h"
#endif /*USE_G10CODE_RAPDU*/

#if defined(GNUPG_SCD_MAIN_HEADER)
#include GNUPG_SCD_MAIN_HEADER
#elif GNUPG_MAJOR_VERSION == 1
/* This is used with GnuPG version < 1.9.  The code has been source
   copied from the current GnuPG >= 1.9  and is maintained over
   there. */
#include "../common/i18n.h"
#include "../common/options.h"
#include "../common/util.h"
#include "cardglue.h"
#include "dynload.h"
#include "errors.h"
#include "memory.h"
#else /* GNUPG_MAJOR_VERSION != 1 */
#include "../common/exechelp.h"
#include "scdaemon.h"
#endif /* GNUPG_MAJOR_VERSION != 1 */
#include "../common/host2net.h"

#include "apdu.h"
#include "iso7816.h"
#define CCID_DRIVER_INCLUDE_USB_IDS 1
#include "ccid-driver.h"

struct dev_list {
  struct ccid_dev_table *ccid_table;
  const char *portstr;
  int idx;
  int idx_max;
};

#define MAX_READER 4 /* Number of readers we support concurrently. */

static int apdu_get_status_internal(int slot, int hang, unsigned int *status,
                                    int on_wire);

/* A structure to collect information pertaining to one reader
   slot. */
struct reader_table_s {
  int used;            /* True if slot is used. */
  unsigned short port; /* Port number:  0 = unused, 1 - dev/tty */

  /* Function pointers initialized to the various backends.  */
  int (*connect_card)(int);
  int (*disconnect_card)(int);
  int (*close_reader)(int);
  int (*reset_reader)(int);
  int (*get_status_reader)(int, unsigned int *, int);
  int (*send_apdu_reader)(int, unsigned char *, size_t, unsigned char *,
                          size_t *, pininfo_t *);
  int (*check_pinpad)(int, int, pininfo_t *);
  void (*dump_status_reader)(int);
  int (*set_progress_cb)(int, gcry_handler_progress_t, void *);
  int (*pinpad_verify)(int, int, int, int, int, pininfo_t *);
  int (*pinpad_modify)(int, int, int, int, int, pininfo_t *);

  struct {
    ccid_driver_t handle;
  } ccid;
#ifdef USE_G10CODE_RAPDU
  struct {
    rapdu_t handle;
  } rapdu;
#endif                    /*USE_G10CODE_RAPDU*/
  char *rdrname;          /* Name of the connected reader or NULL if unknown. */
  unsigned int is_t0 : 1; /* True if we know that we are running T=0. */
  unsigned int is_spr532 : 1; /* True if we know that the reader is a SPR532. */
  unsigned int pinpad_varlen_supported : 1; /* True if we know that the reader
                                               supports variable length pinpad
                                               input.  */
  unsigned int require_get_status : 1;
  unsigned char atr[33];
  size_t atrlen; /* A zero length indicates that the ATR has
                    not yet been read; i.e. the card is not
                    ready for use. */
  std::mutex lock;
};
typedef struct reader_table_s *reader_table_t;

/* A global table to keep track of active readers. */
static struct reader_table_s reader_table[MAX_READER];

static std::mutex reader_table_lock;

/*
      Helper
 */

static int lock_slot(int slot) {
  reader_table[slot].lock.lock();
  return 0;
}

static int trylock_slot(int slot) {
  if (!reader_table[slot].lock.try_lock())
    return SW_HOST_BUSY;
  return 0;
}

static void unlock_slot(int slot) {
  reader_table[slot].lock.unlock();
}

/* Find an unused reader slot for PORTSTR and put it into the reader
   table.  Return -1 on error or the index into the reader table.
   Acquire slot's lock on successful return.  Caller needs to unlock it.  */
static int new_reader_slot(void) {
  int i, reader = -1;

  for (i = 0; i < MAX_READER; i++)
    if (!reader_table[i].used) {
      reader = i;
      reader_table[reader].used = 1;
      break;
    }

  if (reader == -1) {
    log_error("new_reader_slot: out of slots\n");
    return -1;
  }

  if (lock_slot(reader)) {
    reader_table[reader].used = 0;
    return -1;
  }

  reader_table[reader].connect_card = NULL;
  reader_table[reader].disconnect_card = NULL;
  reader_table[reader].close_reader = NULL;
  reader_table[reader].reset_reader = NULL;
  reader_table[reader].get_status_reader = NULL;
  reader_table[reader].send_apdu_reader = NULL;
  reader_table[reader].dump_status_reader = NULL;
  reader_table[reader].set_progress_cb = NULL;

  reader_table[reader].is_t0 = 1;
  reader_table[reader].is_spr532 = 0;
  reader_table[reader].pinpad_varlen_supported = 0;
  reader_table[reader].require_get_status = 1;

  return reader;
}

static void dump_reader_status(int slot) {
  if (!opt.verbose) return;

  if (reader_table[slot].dump_status_reader)
    reader_table[slot].dump_status_reader(slot);

  if (reader_table[slot].atrlen) {
    log_info("slot %d: ATR=", slot);
    log_printhex("", reader_table[slot].atr, reader_table[slot].atrlen);
  }
}

static const char *host_sw_string(long err) {
  switch (err) {
    case 0:
      return "okay";
    case SW_HOST_OUT_OF_CORE:
      return "out of core";
    case SW_HOST_INV_VALUE:
      return "invalid value";
    case SW_HOST_NO_DRIVER:
      return "no driver";
    case SW_HOST_NOT_SUPPORTED:
      return "not supported";
    case SW_HOST_LOCKING_FAILED:
      return "locking failed";
    case SW_HOST_BUSY:
      return "busy";
    case SW_HOST_NO_CARD:
      return "no card";
    case SW_HOST_CARD_INACTIVE:
      return "card inactive";
    case SW_HOST_CARD_IO_ERROR:
      return "card I/O error";
    case SW_HOST_GENERAL_ERROR:
      return "general error";
    case SW_HOST_NO_READER:
      return "no reader";
    case SW_HOST_ABORTED:
      return "aborted";
    case SW_HOST_NO_PINPAD:
      return "no pinpad";
    case SW_HOST_ALREADY_CONNECTED:
      return "already connected";
    default:
      return "unknown host status error";
  }
}

const char *apdu_strerror(int rc) {
  switch (rc) {
    case SW_EOF_REACHED:
      return "eof reached";
    case SW_EEPROM_FAILURE:
      return "eeprom failure";
    case SW_WRONG_LENGTH:
      return "wrong length";
    case SW_CHV_WRONG:
      return "CHV wrong";
    case SW_CHV_BLOCKED:
      return "CHV blocked";
    case SW_REF_DATA_INV:
      return "referenced data invalidated";
    case SW_USE_CONDITIONS:
      return "use conditions not satisfied";
    case SW_BAD_PARAMETER:
      return "bad parameter";
    case SW_NOT_SUPPORTED:
      return "not supported";
    case SW_FILE_NOT_FOUND:
      return "file not found";
    case SW_RECORD_NOT_FOUND:
      return "record not found";
    case SW_REF_NOT_FOUND:
      return "reference not found";
    case SW_NOT_ENOUGH_MEMORY:
      return "not enough memory space in the file";
    case SW_INCONSISTENT_LC:
      return "Lc inconsistent with TLV structure.";
    case SW_INCORRECT_P0_P1:
      return "incorrect parameters P0,P1";
    case SW_BAD_LC:
      return "Lc inconsistent with P0,P1";
    case SW_BAD_P0_P1:
      return "bad P0,P1";
    case SW_INS_NOT_SUP:
      return "instruction not supported";
    case SW_CLA_NOT_SUP:
      return "class not supported";
    case SW_SUCCESS:
      return "success";
    default:
      if ((rc & ~0x00ff) == SW_MORE_DATA) return "more data available";
      if ((rc & 0x10000)) return host_sw_string(rc);
      return "unknown status error";
  }
}

#ifdef HAVE_LIBUSB
/*
     Internal CCID driver interface.
 */

static void dump_ccid_reader_status(int slot) {
  log_info("reader slot %d: using ccid driver\n", slot);
}

static int close_ccid_reader(int slot) {
  ccid_close_reader(reader_table[slot].ccid.handle);
  return 0;
}

static int reset_ccid_reader(int slot) {
  int err;
  reader_table_t slotp = reader_table + slot;
  unsigned char atr[33];
  size_t atrlen;

  err = ccid_get_atr(slotp->ccid.handle, atr, sizeof atr, &atrlen);
  if (err) return err;
  /* If the reset was successful, update the ATR. */
  assert(sizeof slotp->atr >= sizeof atr);
  slotp->atrlen = atrlen;
  memcpy(slotp->atr, atr, atrlen);
  dump_reader_status(slot);
  return 0;
}

static int set_progress_cb_ccid_reader(int slot, gcry_handler_progress_t cb,
                                       void *cb_arg) {
  reader_table_t slotp = reader_table + slot;

  return ccid_set_progress_cb(slotp->ccid.handle, cb, cb_arg);
}

static int get_status_ccid(int slot, unsigned int *status, int on_wire) {
  int rc;
  int bits;

  rc = ccid_slot_status(reader_table[slot].ccid.handle, &bits, on_wire);
  if (rc) return rc;

  if (bits == 0)
    *status = (APDU_CARD_USABLE | APDU_CARD_PRESENT | APDU_CARD_ACTIVE);
  else if (bits == 1)
    *status = APDU_CARD_PRESENT;
  else
    *status = 0;

  return 0;
}

/* Actually send the APDU of length APDULEN to SLOT and return a
   maximum of *BUFLEN data in BUFFER, the actual returned size will be
   set to BUFLEN.  Returns: Internal CCID driver error code. */
static int send_apdu_ccid(int slot, unsigned char *apdu, size_t apdulen,
                          unsigned char *buffer, size_t *buflen,
                          pininfo_t *pininfo) {
  long err;
  size_t maxbuflen;

  /* If we don't have an ATR, we need to reset the reader first. */
  if (!reader_table[slot].atrlen && (err = reset_ccid_reader(slot))) return err;

  if (DBG_CARD_IO) log_printhex(" raw apdu:", apdu, apdulen);

  maxbuflen = *buflen;
  if (pininfo)
    err = ccid_transceive_secure(reader_table[slot].ccid.handle, apdu, apdulen,
                                 pininfo, buffer, maxbuflen, buflen);
  else
    err = ccid_transceive(reader_table[slot].ccid.handle, apdu, apdulen, buffer,
                          maxbuflen, buflen);
  if (err) log_error("ccid_transceive failed: (0x%lx)\n", err);

  return err;
}

/* Check whether the CCID reader supports the ISO command code COMMAND
   on the pinpad.  Return 0 on success.  For a description of the pin
   parameters, see ccid-driver.c */
static int check_ccid_pinpad(int slot, int command, pininfo_t *pininfo) {
  unsigned char apdu[] = {0, 0, 0, 0x81};

  apdu[1] = command;
  return ccid_transceive_secure(reader_table[slot].ccid.handle, apdu,
                                sizeof apdu, pininfo, NULL, 0, NULL);
}

static int ccid_pinpad_operation(int slot, int klasse, int ins, int p0, int p1,
                                 pininfo_t *pininfo) {
  unsigned char apdu[4];
  int err, sw;
  unsigned char result[2];
  size_t resultlen = 2;

  apdu[0] = klasse;
  apdu[1] = ins;
  apdu[2] = p0;
  apdu[3] = p1;
  err = ccid_transceive_secure(reader_table[slot].ccid.handle, apdu,
                               sizeof apdu, pininfo, result, 2, &resultlen);
  if (err) return err;

  if (resultlen < 2) return SW_HOST_INCOMPLETE_CARD_RESPONSE;

  sw = (result[resultlen - 2] << 8) | result[resultlen - 1];
  return sw;
}

/* Open the reader and try to read an ATR.  */
static int open_ccid_reader(struct dev_list *dl) {
  int err;
  int slot;
  int require_get_status;
  reader_table_t slotp;

  slot = new_reader_slot();
  if (slot == -1) return -1;
  slotp = reader_table + slot;

  err = ccid_open_reader(dl->portstr, dl->idx, dl->ccid_table,
                         &slotp->ccid.handle, &slotp->rdrname);
  if (!err)
    err = ccid_get_atr(slotp->ccid.handle, slotp->atr, sizeof slotp->atr,
                       &slotp->atrlen);
  if (err) {
    slotp->used = 0;
    unlock_slot(slot);
    return -1;
  }

  require_get_status = ccid_require_get_status(slotp->ccid.handle);

  reader_table[slot].close_reader = close_ccid_reader;
  reader_table[slot].reset_reader = reset_ccid_reader;
  reader_table[slot].get_status_reader = get_status_ccid;
  reader_table[slot].send_apdu_reader = send_apdu_ccid;
  reader_table[slot].check_pinpad = check_ccid_pinpad;
  reader_table[slot].dump_status_reader = dump_ccid_reader_status;
  reader_table[slot].set_progress_cb = set_progress_cb_ccid_reader;
  reader_table[slot].pinpad_verify = ccid_pinpad_operation;
  reader_table[slot].pinpad_modify = ccid_pinpad_operation;
  /* Our CCID reader code does not support T=0 at all, thus reset the
     flag.  */
  reader_table[slot].is_t0 = 0;
  reader_table[slot].require_get_status = require_get_status;

  dump_reader_status(slot);
  unlock_slot(slot);
  return slot;
}
#endif /* HAVE_LIBUSB */

#ifdef USE_G10CODE_RAPDU
/*
     The Remote APDU Interface.

     This uses the Remote APDU protocol to contact a reader.

     The port number is actually an index into the list of ports as
     returned via the protocol.
 */

static int rapdu_status_to_sw(int status) {
  int rc;

  switch (status) {
    case RAPDU_STATUS_SUCCESS:
      rc = 0;
      break;

    case RAPDU_STATUS_INVCMD:
    case RAPDU_STATUS_INVPROT:
    case RAPDU_STATUS_INVSEQ:
    case RAPDU_STATUS_INVCOOKIE:
    case RAPDU_STATUS_INVREADER:
      rc = SW_HOST_INV_VALUE;
      break;

    case RAPDU_STATUS_TIMEOUT:
      rc = SW_HOST_CARD_IO_ERROR;
      break;
    case RAPDU_STATUS_CARDIO:
      rc = SW_HOST_CARD_IO_ERROR;
      break;
    case RAPDU_STATUS_NOCARD:
      rc = SW_HOST_NO_CARD;
      break;
    case RAPDU_STATUS_CARDCHG:
      rc = SW_HOST_NO_CARD;
      break;
    case RAPDU_STATUS_BUSY:
      rc = SW_HOST_BUSY;
      break;
    case RAPDU_STATUS_NEEDRESET:
      rc = SW_HOST_CARD_INACTIVE;
      break;

    default:
      rc = SW_HOST_GENERAL_ERROR;
      break;
  }

  return rc;
}

static int close_rapdu_reader(int slot) {
  rapdu_release(reader_table[slot].rapdu.handle);
  return 0;
}

static int reset_rapdu_reader(int slot) {
  int err;
  reader_table_t slotp;
  rapdu_msg_t msg = NULL;

  slotp = reader_table + slot;

  err = rapdu_send_cmd(slotp->rapdu.handle, RAPDU_CMD_RESET);
  if (err) {
    log_error("sending rapdu command RESET failed: %s\n",
              err < 0 ? strerror(errno) : rapdu_strerror(err));
    rapdu_msg_release(msg);
    return rapdu_status_to_sw(err);
  }
  err = rapdu_read_msg(slotp->rapdu.handle, &msg);
  if (err) {
    log_error("receiving rapdu message failed: %s\n",
              err < 0 ? strerror(errno) : rapdu_strerror(err));
    rapdu_msg_release(msg);
    return rapdu_status_to_sw(err);
  }
  if (msg->cmd != RAPDU_STATUS_SUCCESS || !msg->datalen) {
    int sw = rapdu_status_to_sw(msg->cmd);
    log_error("rapdu command RESET failed: %s\n", rapdu_strerror(msg->cmd));
    rapdu_msg_release(msg);
    return sw;
  }
  if (msg->datalen > DIM(slotp->atr)) {
    log_error("ATR returned by the RAPDU layer is too large\n");
    rapdu_msg_release(msg);
    return SW_HOST_INV_VALUE;
  }
  slotp->atrlen = msg->datalen;
  memcpy(slotp->atr, msg->data, msg->datalen);

  rapdu_msg_release(msg);
  return 0;
}

static int my_rapdu_get_status(int slot, unsigned int *status, int on_wire) {
  int err;
  reader_table_t slotp;
  rapdu_msg_t msg = NULL;
  int oldslot;

  (void)on_wire;
  slotp = reader_table + slot;

  oldslot = rapdu_set_reader(slotp->rapdu.handle, slot);
  err = rapdu_send_cmd(slotp->rapdu.handle, RAPDU_CMD_GET_STATUS);
  rapdu_set_reader(slotp->rapdu.handle, oldslot);
  if (err) {
    log_error("sending rapdu command GET_STATUS failed: %s\n",
              err < 0 ? strerror(errno) : rapdu_strerror(err));
    return rapdu_status_to_sw(err);
  }
  err = rapdu_read_msg(slotp->rapdu.handle, &msg);
  if (err) {
    log_error("receiving rapdu message failed: %s\n",
              err < 0 ? strerror(errno) : rapdu_strerror(err));
    rapdu_msg_release(msg);
    return rapdu_status_to_sw(err);
  }
  if (msg->cmd != RAPDU_STATUS_SUCCESS || !msg->datalen) {
    int sw = rapdu_status_to_sw(msg->cmd);
    log_error("rapdu command GET_STATUS failed: %s\n",
              rapdu_strerror(msg->cmd));
    rapdu_msg_release(msg);
    return sw;
  }
  *status = msg->data[0];

  rapdu_msg_release(msg);
  return 0;
}

/* Actually send the APDU of length APDULEN to SLOT and return a
   maximum of *BUFLEN data in BUFFER, the actual returned size will be
   set to BUFLEN.  Returns: APDU error code. */
static int my_rapdu_send_apdu(int slot, unsigned char *apdu, size_t apdulen,
                              unsigned char *buffer, size_t *buflen,
                              pininfo_t *pininfo) {
  int err;
  reader_table_t slotp;
  rapdu_msg_t msg = NULL;
  size_t maxlen = *buflen;

  slotp = reader_table + slot;

  *buflen = 0;
  if (DBG_CARD_IO) log_printhex("  APDU_data:", apdu, apdulen);

  if (apdulen < 4) {
    log_error("rapdu_send_apdu: APDU is too short\n");
    return SW_HOST_INV_VALUE;
  }

  err = rapdu_send_apdu(slotp->rapdu.handle, apdu, apdulen);
  if (err) {
    log_error("sending rapdu command APDU failed: %s\n",
              err < 0 ? strerror(errno) : rapdu_strerror(err));
    rapdu_msg_release(msg);
    return rapdu_status_to_sw(err);
  }
  err = rapdu_read_msg(slotp->rapdu.handle, &msg);
  if (err) {
    log_error("receiving rapdu message failed: %s\n",
              err < 0 ? strerror(errno) : rapdu_strerror(err));
    rapdu_msg_release(msg);
    return rapdu_status_to_sw(err);
  }
  if (msg->cmd != RAPDU_STATUS_SUCCESS || !msg->datalen) {
    int sw = rapdu_status_to_sw(msg->cmd);
    log_error("rapdu command APDU failed: %s\n", rapdu_strerror(msg->cmd));
    rapdu_msg_release(msg);
    return sw;
  }

  if (msg->datalen > maxlen) {
    log_error("rapdu response apdu too large\n");
    rapdu_msg_release(msg);
    return SW_HOST_INV_VALUE;
  }

  *buflen = msg->datalen;
  memcpy(buffer, msg->data, msg->datalen);

  rapdu_msg_release(msg);
  return 0;
}

static int open_rapdu_reader(
    int portno, const unsigned char *cookie, size_t length,
    int (*readfnc)(void *opaque, void *buffer, size_t size),
    void *readfnc_value,
    int (*writefnc)(void *opaque, const void *buffer, size_t size),
    void *writefnc_value, void (*closefnc)(void *opaque),
    void *closefnc_value) {
  int err;
  int slot;
  reader_table_t slotp;
  rapdu_msg_t msg = NULL;

  slot = new_reader_slot();
  if (slot == -1) return -1;
  slotp = reader_table + slot;

  slotp->rapdu.handle = rapdu_new();
  if (!slotp->rapdu.handle) {
    slotp->used = 0;
    unlock_slot(slot);
    return -1;
  }

  rapdu_set_reader(slotp->rapdu.handle, portno);

  rapdu_set_iofunc(slotp->rapdu.handle, readfnc, readfnc_value, writefnc,
                   writefnc_value, closefnc, closefnc_value);
  rapdu_set_cookie(slotp->rapdu.handle, cookie, length);

  /* First try to get the current ATR, but if the card is inactive
     issue a reset instead.  */
  err = rapdu_send_cmd(slotp->rapdu.handle, RAPDU_CMD_GET_ATR);
  if (err == RAPDU_STATUS_NEEDRESET)
    err = rapdu_send_cmd(slotp->rapdu.handle, RAPDU_CMD_RESET);
  if (err) {
    log_info("sending rapdu command GET_ATR/RESET failed: %s\n",
             err < 0 ? strerror(errno) : rapdu_strerror(err));
    goto failure;
  }
  err = rapdu_read_msg(slotp->rapdu.handle, &msg);
  if (err) {
    log_info("receiving rapdu message failed: %s\n",
             err < 0 ? strerror(errno) : rapdu_strerror(err));
    goto failure;
  }
  if (msg->cmd != RAPDU_STATUS_SUCCESS || !msg->datalen) {
    log_info("rapdu command GET ATR failed: %s\n", rapdu_strerror(msg->cmd));
    goto failure;
  }
  if (msg->datalen > DIM(slotp->atr)) {
    log_error("ATR returned by the RAPDU layer is too large\n");
    goto failure;
  }
  slotp->atrlen = msg->datalen;
  memcpy(slotp->atr, msg->data, msg->datalen);

  reader_table[slot].close_reader = close_rapdu_reader;
  reader_table[slot].reset_reader = reset_rapdu_reader;
  reader_table[slot].get_status_reader = my_rapdu_get_status;
  reader_table[slot].send_apdu_reader = my_rapdu_send_apdu;
  reader_table[slot].check_pinpad = NULL;
  reader_table[slot].dump_status_reader = NULL;
  reader_table[slot].pinpad_verify = NULL;
  reader_table[slot].pinpad_modify = NULL;

  dump_reader_status(slot);
  rapdu_msg_release(msg);
  unlock_slot(slot);
  return slot;

failure:
  rapdu_msg_release(msg);
  rapdu_release(slotp->rapdu.handle);
  slotp->used = 0;
  unlock_slot(slot);
  return -1;
}

#endif /*USE_G10CODE_RAPDU*/

/*
       Driver Access
 */
gpg_error_t apdu_dev_list_start(const char *portstr, struct dev_list **l_p) {
  struct dev_list *dl = (dev_list *)xtrymalloc(sizeof(struct dev_list));

  *l_p = NULL;
  if (!dl) return gpg_error_from_syserror();

  dl->portstr = portstr;
  dl->idx = 0;

  reader_table_lock.lock();

#ifdef HAVE_LIBUSB
  if (opt.disable_ccid) {
    dl->ccid_table = NULL;
    dl->idx_max = 1;
  } else {
    gpg_error_t err;

    err = ccid_dev_scan(&dl->idx_max, &dl->ccid_table);
    if (err) return err;

    if (dl->idx_max == 0) {
      /* If a CCID reader specification has been given, the user does
         not want a fallback to other drivers. */
      if (portstr && strlen(portstr) > 5 && portstr[4] == ':') {
        if (DBG_READER)
          log_debug("leave: apdu_open_reader => slot=-1 (no ccid)\n");

        xfree(dl);
        reader_table_lock.unlock();
        return GPG_ERR_ENODEV;
      } else
        dl->idx_max = 1;
    }
  }
#else
  dl->ccid_table = NULL;
  dl->idx_max = 1;
#endif /* HAVE_LIBUSB */

  *l_p = dl;
  return 0;
}

void apdu_dev_list_finish(struct dev_list *dl) {
#ifdef HAVE_LIBUSB
  if (dl->ccid_table) ccid_dev_scan_finish(dl->ccid_table, dl->idx_max);
#endif
  xfree(dl);
  reader_table_lock.unlock();
}

int apdu_open_reader(struct dev_list *dl, int app_empty) {
  int slot;

#ifdef HAVE_LIBUSB
  if (dl->ccid_table) { /* CCID readers.  */
    int readerno;

    /* See whether we want to use the reader ID string or a reader
       number. A readerno of -1 indicates that the reader ID string is
       to be used. */
    if (dl->portstr && strchr(dl->portstr, ':'))
      readerno = -1; /* We want to use the readerid.  */
    else if (dl->portstr) {
      readerno = atoi(dl->portstr);
      if (readerno < 0) {
        return -1;
      }
    } else
      readerno = 0; /* Default. */

    if (readerno > 0) { /* Use single, the specific reader.  */
      if (readerno >= dl->idx_max) return -1;

      dl->idx = readerno;
      dl->portstr = NULL;
      slot = open_ccid_reader(dl);
      dl->idx = dl->idx_max;
      if (slot >= 0)
        return slot;
      else
        return -1;
    }

    while (dl->idx < dl->idx_max) {
      unsigned int bai = ccid_get_BAI(dl->idx, dl->ccid_table);

      if (DBG_READER) log_debug("apdu_open_reader: BAI=%x\n", bai);

      /* Check identity by BAI against already opened HANDLEs.  */
      for (slot = 0; slot < MAX_READER; slot++)
        if (reader_table[slot].used && reader_table[slot].ccid.handle &&
            ccid_compare_BAI(reader_table[slot].ccid.handle, bai))
          break;

      if (slot == MAX_READER) { /* Found a new device.  */
        if (DBG_READER) log_debug("apdu_open_reader: new device=%x\n", bai);

        slot = open_ccid_reader(dl);

        dl->idx++;
        if (slot >= 0)
          return slot;
        else {
          /* Skip this reader.  */
          log_error("ccid open error: skip\n");
          continue;
        }
      } else
        dl->idx++;
    }

    slot = -1;
  } else
#endif
    slot = -1;

  return slot;
}

/* Open an remote reader and return an internal slot number or -1 on
   error. This function is an alternative to apdu_open_reader and used
   with remote readers only.  Note that the supplied CLOSEFNC will
   only be called once and the slot will not be valid afther this.

   If PORTSTR is NULL we default to the first available port.
*/
int apdu_open_remote_reader(
    const char *portstr, const unsigned char *cookie, size_t length,
    int (*readfnc)(void *opaque, void *buffer, size_t size),
    void *readfnc_value,
    int (*writefnc)(void *opaque, const void *buffer, size_t size),
    void *writefnc_value, void (*closefnc)(void *opaque),
    void *closefnc_value) {
#ifdef USE_G10CODE_RAPDU
  return open_rapdu_reader(portstr ? atoi(portstr) : 0, cookie, length, readfnc,
                           readfnc_value, writefnc, writefnc_value, closefnc,
                           closefnc_value);
#else
  (void)portstr;
  (void)cookie;
  (void)length;
  (void)readfnc;
  (void)readfnc_value;
  (void)writefnc;
  (void)writefnc_value;
  (void)closefnc;
  (void)closefnc_value;
#ifdef _WIN32
  errno = ENOENT;
#else
  errno = ENOSYS;
#endif
  return -1;
#endif
}

int apdu_close_reader(int slot) {
  int sw;

  if (DBG_READER) log_debug("enter: apdu_close_reader: slot=%d\n", slot);

  if (slot < 0 || slot >= MAX_READER || !reader_table[slot].used) {
    if (DBG_READER)
      log_debug("leave: apdu_close_reader => SW_HOST_NO_DRIVER\n");
    return SW_HOST_NO_DRIVER;
  }
  sw = apdu_disconnect(slot);
  if (sw) {
    /*
     * When the reader/token was removed it might come here.
     * It should go through to call CLOSE_READER even if we got an error.
     */
    if (DBG_READER)
      log_debug("apdu_close_reader => 0x%x (apdu_disconnect)\n", sw);
  }
  if (reader_table[slot].close_reader) {
    sw = reader_table[slot].close_reader(slot);
    reader_table[slot].used = 0;
    if (DBG_READER)
      log_debug("leave: apdu_close_reader => 0x%x (close_reader)\n", sw);
    return sw;
  }
  xfree(reader_table[slot].rdrname);
  reader_table[slot].rdrname = NULL;
  reader_table[slot].used = 0;
  if (DBG_READER)
    log_debug("leave: apdu_close_reader => SW_HOST_NOT_SUPPORTED\n");
  return SW_HOST_NOT_SUPPORTED;
}

/* Function suitable for a cleanup function to close all reader.  It
   should not be used if the reader will be opened again.  The reason
   for implementing this to properly close USB devices so that they
   will startup the next time without error. */
void apdu_prepare_exit(void) {
  static int sentinel;
  int slot;

  if (!sentinel) {
    sentinel = 1;
    std::lock_guard<std::mutex> lock(reader_table_lock);
    for (slot = 0; slot < MAX_READER; slot++)
      if (reader_table[slot].used) {
        apdu_disconnect(slot);
        if (reader_table[slot].close_reader)
          reader_table[slot].close_reader(slot);
        xfree(reader_table[slot].rdrname);
        reader_table[slot].rdrname = NULL;
        reader_table[slot].used = 0;
      }
    sentinel = 0;
  }
}

/* Enumerate all readers and return information on whether this reader
   is in use.  The caller should start with SLOT set to 0 and
   increment it with each call until an error is returned. */
int apdu_enum_reader(int slot, int *used) {
  if (slot < 0 || slot >= MAX_READER) return SW_HOST_NO_DRIVER;
  *used = reader_table[slot].used;
  return 0;
}

/* Connect a card.  This is used to power up the card and make sure
   that an ATR is available.  Depending on the reader backend it may
   return an error for an inactive card or if no card is available.
   Return -1 on error.  Return 1 if reader requires get_status to
   watch card removal.  Return 0 if it's a token (always with a card),
   or it supports INTERRUPT endpoint to watch card removal.
  */
int apdu_connect(int slot) {
  int sw = 0;
  unsigned int status = 0;

  if (DBG_READER) log_debug("enter: apdu_connect: slot=%d\n", slot);

  if (slot < 0 || slot >= MAX_READER || !reader_table[slot].used) {
    if (DBG_READER) log_debug("leave: apdu_connect => SW_HOST_NO_DRIVER\n");
    return -1;
  }

  /* Only if the access method provides a connect function we use it.
     If not, we expect that the card has been implicitly connected by
     apdu_open_reader.  */
  if (reader_table[slot].connect_card) {
    sw = lock_slot(slot);
    if (!sw) {
      sw = reader_table[slot].connect_card(slot);
      unlock_slot(slot);
    }
  }

  /* We need to call apdu_get_status_internal, so that the last-status
     machinery gets setup properly even if a card is inserted while
     scdaemon is fired up and apdu_get_status has not yet been called.
     Without that we would force a reset of the card with the next
     call to apdu_get_status.  */
  if (!sw) sw = apdu_get_status_internal(slot, 1, &status, 1);

  if (sw)
    ;
  else if (!(status & APDU_CARD_PRESENT))
    sw = SW_HOST_NO_CARD;
  else if ((status & APDU_CARD_PRESENT) && !(status & APDU_CARD_ACTIVE))
    sw = SW_HOST_CARD_INACTIVE;

  if (sw == SW_HOST_CARD_INACTIVE) {
    /* Try power it up again.  */
    sw = apdu_reset(slot);
  }

  if (DBG_READER) log_debug("leave: apdu_connect => sw=0x%x\n", sw);

  if (sw) return -1;

  return reader_table[slot].require_get_status;
}

int apdu_disconnect(int slot) {
  int sw;

  if (DBG_READER) log_debug("enter: apdu_disconnect: slot=%d\n", slot);

  if (slot < 0 || slot >= MAX_READER || !reader_table[slot].used) {
    if (DBG_READER) log_debug("leave: apdu_disconnect => SW_HOST_NO_DRIVER\n");
    return SW_HOST_NO_DRIVER;
  }

  if (reader_table[slot].disconnect_card) {
    sw = lock_slot(slot);
    if (!sw) {
      sw = reader_table[slot].disconnect_card(slot);
      unlock_slot(slot);
    }
  } else
    sw = 0;

  if (DBG_READER) log_debug("leave: apdu_disconnect => sw=0x%x\n", sw);
  return sw;
}

/* Set the progress callback of SLOT to CB and its args to CB_ARG.  If
   CB is NULL the progress callback is removed.  */
int apdu_set_progress_cb(int slot, gcry_handler_progress_t cb, void *cb_arg) {
  int sw;

  if (slot < 0 || slot >= MAX_READER || !reader_table[slot].used)
    return SW_HOST_NO_DRIVER;

  if (reader_table[slot].set_progress_cb) {
    sw = lock_slot(slot);
    if (!sw) {
      sw = reader_table[slot].set_progress_cb(slot, cb, cb_arg);
      unlock_slot(slot);
    }
  } else
    sw = 0;
  return sw;
}

/* Do a reset for the card in reader at SLOT. */
int apdu_reset(int slot) {
  int sw;

  if (DBG_READER) log_debug("enter: apdu_reset: slot=%d\n", slot);

  if (slot < 0 || slot >= MAX_READER || !reader_table[slot].used) {
    if (DBG_READER) log_debug("leave: apdu_reset => SW_HOST_NO_DRIVER\n");
    return SW_HOST_NO_DRIVER;
  }

  if ((sw = lock_slot(slot))) {
    if (DBG_READER) log_debug("leave: apdu_reset => sw=0x%x (lock_slot)\n", sw);
    return sw;
  }

  if (reader_table[slot].reset_reader)
    sw = reader_table[slot].reset_reader(slot);

  unlock_slot(slot);
  if (DBG_READER) log_debug("leave: apdu_reset => sw=0x%x\n", sw);
  return sw;
}

/* Return the ATR or NULL if none is available.  On success the length
   of the ATR is stored at ATRLEN.  The caller must free the returned
   value.  */
unsigned char *apdu_get_atr(int slot, size_t *atrlen) {
  unsigned char *buf;

  if (DBG_READER) log_debug("enter: apdu_get_atr: slot=%d\n", slot);

  if (slot < 0 || slot >= MAX_READER || !reader_table[slot].used) {
    if (DBG_READER) log_debug("leave: apdu_get_atr => NULL (bad slot)\n");
    return NULL;
  }
  if (!reader_table[slot].atrlen) {
    if (DBG_READER) log_debug("leave: apdu_get_atr => NULL (no ATR)\n");
    return NULL;
  }

  buf = (unsigned char *)xtrymalloc(reader_table[slot].atrlen);
  if (!buf) {
    if (DBG_READER) log_debug("leave: apdu_get_atr => NULL (out of core)\n");
    return NULL;
  }
  memcpy(buf, reader_table[slot].atr, reader_table[slot].atrlen);
  *atrlen = reader_table[slot].atrlen;
  if (DBG_READER) log_debug("leave: apdu_get_atr => atrlen=%zu\n", *atrlen);
  return buf;
}

/* Retrieve the status for SLOT. The function does only wait for the
   card to become available if HANG is set to true. On success the
   bits in STATUS will be set to

     APDU_CARD_USABLE  (bit 0) = card present and usable
     APDU_CARD_PRESENT (bit 1) = card present
     APDU_CARD_ACTIVE  (bit 2) = card active
                       (bit 3) = card access locked [not yet implemented]

   For most applications, testing bit 0 is sufficient.
*/
static int apdu_get_status_internal(int slot, int hang, unsigned int *status,
                                    int on_wire) {
  int sw;
  unsigned int s = 0;

  if (slot < 0 || slot >= MAX_READER || !reader_table[slot].used)
    return SW_HOST_NO_DRIVER;

  if ((sw = hang ? lock_slot(slot) : trylock_slot(slot))) return sw;

  if (reader_table[slot].get_status_reader)
    sw = reader_table[slot].get_status_reader(slot, &s, on_wire);

  unlock_slot(slot);

  if (sw) {
    if (on_wire) reader_table[slot].atrlen = 0;
    s = 0;
  }

  if (status) *status = s;
  return sw;
}

/* See above for a description.  */
int apdu_get_status(int slot, int hang, unsigned int *status) {
  int sw;

  if (DBG_READER)
    log_debug("enter: apdu_get_status: slot=%d hang=%d\n", slot, hang);
  sw = apdu_get_status_internal(slot, hang, status, 0);
  if (DBG_READER) {
    if (status)
      log_debug("leave: apdu_get_status => sw=0x%x status=%u\n", sw, *status);
    else
      log_debug("leave: apdu_get_status => sw=0x%x\n", sw);
  }
  return sw;
}

/* Check whether the reader supports the ISO command code COMMAND on
   the pinpad.  Return 0 on success.  For a description of the pin
   parameters, see ccid-driver.c */
int apdu_check_pinpad(int slot, int command, pininfo_t *pininfo) {
  if (slot < 0 || slot >= MAX_READER || !reader_table[slot].used)
    return SW_HOST_NO_DRIVER;

  if (opt.enable_pinpad_varlen) pininfo->fixedlen = 0;

  if (reader_table[slot].check_pinpad) {
    int sw;

    if ((sw = lock_slot(slot))) return sw;

    sw = reader_table[slot].check_pinpad(slot, command, pininfo);
    unlock_slot(slot);
    return sw;
  } else
    return SW_HOST_NOT_SUPPORTED;
}

int apdu_pinpad_verify(int slot, int klasse, int ins, int p0, int p1,
                       pininfo_t *pininfo) {
  if (slot < 0 || slot >= MAX_READER || !reader_table[slot].used)
    return SW_HOST_NO_DRIVER;

  if (reader_table[slot].pinpad_verify) {
    int sw;

    if ((sw = lock_slot(slot))) return sw;

    sw = reader_table[slot].pinpad_verify(slot, klasse, ins, p0, p1, pininfo);
    unlock_slot(slot);
    return sw;
  } else
    return SW_HOST_NOT_SUPPORTED;
}

int apdu_pinpad_modify(int slot, int klasse, int ins, int p0, int p1,
                       pininfo_t *pininfo) {
  if (slot < 0 || slot >= MAX_READER || !reader_table[slot].used)
    return SW_HOST_NO_DRIVER;

  if (reader_table[slot].pinpad_modify) {
    int sw;

    if ((sw = lock_slot(slot))) return sw;

    sw = reader_table[slot].pinpad_modify(slot, klasse, ins, p0, p1, pininfo);
    unlock_slot(slot);
    return sw;
  } else
    return SW_HOST_NOT_SUPPORTED;
}

/* Dispatcher for the actual send_apdu function. Note, that this
   function should be called in locked state. */
static int send_apdu(int slot, unsigned char *apdu, size_t apdulen,
                     unsigned char *buffer, size_t *buflen,
                     pininfo_t *pininfo) {
  if (slot < 0 || slot >= MAX_READER || !reader_table[slot].used)
    return SW_HOST_NO_DRIVER;

  if (reader_table[slot].send_apdu_reader)
    return reader_table[slot].send_apdu_reader(slot, apdu, apdulen, buffer,
                                               buflen, pininfo);
  else
    return SW_HOST_NOT_SUPPORTED;
}

/* Core APDU tranceiver function. Parameters are described at
   apdu_send_le with the exception of PININFO which indicates pinpad
   related operations if not NULL.  If EXTENDED_MODE is not 0
   command chaining or extended length will be used according to these
   values:
       n < 0 := Use command chaining with the data part limited to -n
                in each chunk.  If -1 is used a default value is used.
      n == 0 := No extended mode or command chaining.
      n == 1 := Use extended length for input and output without a
                length limit.
       n > 1 := Use extended length with up to N bytes.

*/
static int send_le(int slot, int klasse, int ins, int p0, int p1, int lc,
                   const char *data, int le, unsigned char **retbuf,
                   size_t *retbuflen, pininfo_t *pininfo, int extended_mode) {
#define SHORT_RESULT_BUFFER_SIZE 258
  /* We allocate 8 extra bytes as a safety margin towards a driver bug.  */
  unsigned char short_result_buffer[SHORT_RESULT_BUFFER_SIZE + 10];
  unsigned char *result_buffer = NULL;
  size_t result_buffer_size;
  unsigned char *result;
  size_t resultlen;
  unsigned char short_apdu_buffer[5 + 256 + 1];
  unsigned char *apdu_buffer = NULL;
  size_t apdu_buffer_size;
  unsigned char *apdu;
  size_t apdulen;
  int sw;
  long rc; /* We need a long here due to PC/SC. */
  int did_exact_length_hack = 0;
  int use_chaining = 0;
  int use_extended_length = 0;
  int lc_chunk;

  if (slot < 0 || slot >= MAX_READER || !reader_table[slot].used)
    return SW_HOST_NO_DRIVER;

  if (DBG_CARD_IO)
    log_debug("send apdu: c=%02X i=%02X p1=%02X p2=%02X lc=%d le=%d em=%d\n",
              klasse, ins, p0, p1, lc, le, extended_mode);

  if (lc != -1 && (lc > 255 || lc < 0)) {
    /* Data does not fit into an APDU.  What we do now depends on
       the EXTENDED_MODE parameter.  */
    if (!extended_mode)
      return SW_WRONG_LENGTH; /* No way to send such an APDU.  */
    else if (extended_mode > 0)
      use_extended_length = 1;
    else if (extended_mode < 0) {
      /* Send APDU using chaining mode.  */
      if (lc > 16384) return SW_WRONG_LENGTH; /* Sanity check.  */
      if ((klasse & 0xf0) != 0)
        return SW_HOST_INV_VALUE; /* Upper 4 bits need to be 0.  */
      use_chaining = extended_mode == -1 ? 255 : -extended_mode;
      use_chaining &= 0xff;
    } else
      return SW_HOST_INV_VALUE;
  } else if (lc == -1 && extended_mode > 0)
    use_extended_length = 1;

  if (le != -1 && (le > (extended_mode > 0 ? 255 : 256) || le < 0)) {
    /* Expected Data does not fit into an APDU.  What we do now
       depends on the EXTENDED_MODE parameter.  Note that a check
       for command chaining does not make sense because we are
       looking at Le.  */
    if (!extended_mode)
      return SW_WRONG_LENGTH; /* No way to send such an APDU.  */
    else if (use_extended_length)
      ; /* We are already using extended length.  */
    else if (extended_mode > 0)
      use_extended_length = 1;
    else
      return SW_HOST_INV_VALUE;
  }

  if ((!data && lc != -1) || (data && lc == -1)) return SW_HOST_INV_VALUE;

  if (use_extended_length) {
    if (reader_table[slot].is_t0) return SW_HOST_NOT_SUPPORTED;

    /* Space for: cls/ins/p1/p2+Z+2_byte_Lc+Lc+2_byte_Le.  */
    apdu_buffer_size = 4 + 1 + (lc >= 0 ? (2 + lc) : 0) + 2;
    apdu_buffer = (unsigned char *)xtrymalloc(apdu_buffer_size + 10);
    if (!apdu_buffer) return SW_HOST_OUT_OF_CORE;
    apdu = apdu_buffer;
  } else {
    apdu_buffer_size = sizeof short_apdu_buffer;
    apdu = short_apdu_buffer;
  }

  if (use_extended_length && (le > 256 || le < 0)) {
    /* Two more bytes are needed for status bytes.  */
    result_buffer_size = le < 0 ? 4096 : (le + 2);
    result_buffer = (unsigned char *)xtrymalloc(result_buffer_size);
    if (!result_buffer) {
      xfree(apdu_buffer);
      return SW_HOST_OUT_OF_CORE;
    }
    result = result_buffer;
  } else {
    result_buffer_size = SHORT_RESULT_BUFFER_SIZE;
    result = short_result_buffer;
  }
#undef SHORT_RESULT_BUFFER_SIZE

  if ((sw = lock_slot(slot))) {
    xfree(apdu_buffer);
    xfree(result_buffer);
    return sw;
  }

  do {
    if (use_extended_length) {
      use_chaining = 0;
      apdulen = 0;
      apdu[apdulen++] = klasse;
      apdu[apdulen++] = ins;
      apdu[apdulen++] = p0;
      apdu[apdulen++] = p1;
      if (lc > 0) {
        apdu[apdulen++] = 0; /* Z byte: Extended length marker.  */
        apdu[apdulen++] = ((lc >> 8) & 0xff);
        apdu[apdulen++] = (lc & 0xff);
        memcpy(apdu + apdulen, data, lc);
        data += lc;
        apdulen += lc;
      }
      if (le != -1) {
        if (lc <= 0) apdu[apdulen++] = 0; /* Z byte: Extended length marker.  */
        apdu[apdulen++] = ((le >> 8) & 0xff);
        apdu[apdulen++] = (le & 0xff);
      }
    } else {
      apdulen = 0;
      apdu[apdulen] = klasse;
      if (use_chaining && lc > 255) {
        apdu[apdulen] |= 0x10;
        assert(use_chaining < 256);
        lc_chunk = use_chaining;
        lc -= use_chaining;
      } else {
        use_chaining = 0;
        lc_chunk = lc;
      }
      apdulen++;
      apdu[apdulen++] = ins;
      apdu[apdulen++] = p0;
      apdu[apdulen++] = p1;
      if (lc_chunk != -1) {
        apdu[apdulen++] = lc_chunk;
        memcpy(apdu + apdulen, data, lc_chunk);
        data += lc_chunk;
        apdulen += lc_chunk;
        /* T=0 does not allow the use of Lc together with Le;
           thus disable Le in this case.  */
        if (reader_table[slot].is_t0) le = -1;
      }
      if (le != -1 && !use_chaining)
        apdu[apdulen++] = le; /* Truncation is okay (0 means 256). */
    }

  exact_length_hack:
    /* As a safeguard don't pass any garbage to the driver.  */
    assert(apdulen <= apdu_buffer_size);
    memset(apdu + apdulen, 0, apdu_buffer_size - apdulen);
    resultlen = result_buffer_size;
    rc = send_apdu(slot, apdu, apdulen, result, &resultlen, pininfo);
    if (rc || resultlen < 2) {
      log_info("apdu_send_simple(%d) failed: %s\n", slot, apdu_strerror(rc));
      unlock_slot(slot);
      xfree(apdu_buffer);
      xfree(result_buffer);
      return rc ? rc : SW_HOST_INCOMPLETE_CARD_RESPONSE;
    }
    sw = (result[resultlen - 2] << 8) | result[resultlen - 1];
    if (!use_extended_length && !did_exact_length_hack &&
        SW_EXACT_LENGTH_P(sw)) {
      apdu[apdulen - 1] = (sw & 0x00ff);
      did_exact_length_hack = 1;
      goto exact_length_hack;
    }
  } while (use_chaining && sw == SW_SUCCESS);

  if (apdu_buffer) {
    xfree(apdu_buffer);
    apdu_buffer = NULL;
  }

  /* Store away the returned data but strip the statusword. */
  resultlen -= 2;
  if (DBG_CARD_IO) {
    log_debug(" response: sw=%04X  datalen=%d\n", sw, (unsigned int)resultlen);
    if (!retbuf && (sw == SW_SUCCESS || (sw & 0xff00) == SW_MORE_DATA))
      log_printhex("    dump: ", result, resultlen);
  }

  if (sw == SW_SUCCESS || sw == SW_EOF_REACHED) {
    if (retbuf) {
      *retbuf = (unsigned char *)xtrymalloc(resultlen ? resultlen : 1);
      if (!*retbuf) {
        unlock_slot(slot);
        xfree(result_buffer);
        return SW_HOST_OUT_OF_CORE;
      }
      *retbuflen = resultlen;
      memcpy(*retbuf, result, resultlen);
    }
  } else if ((sw & 0xff00) == SW_MORE_DATA) {
    unsigned char *p = NULL, *tmp;
    size_t bufsize = 4096;

    /* It is likely that we need to return much more data, so we
       start off with a large buffer. */
    if (retbuf) {
      *retbuf = p = (unsigned char *)xtrymalloc(bufsize);
      if (!*retbuf) {
        unlock_slot(slot);
        xfree(result_buffer);
        return SW_HOST_OUT_OF_CORE;
      }
      assert(resultlen < bufsize);
      memcpy(p, result, resultlen);
      p += resultlen;
    }

    do {
      int len = (sw & 0x00ff);

      if (DBG_CARD_IO)
        log_debug("apdu_send_simple(%d): %d more bytes available\n", slot, len);
      apdu_buffer_size = sizeof short_apdu_buffer;
      apdu = short_apdu_buffer;
      apdulen = 0;
      apdu[apdulen++] = klasse;
      apdu[apdulen++] = 0xC0;
      apdu[apdulen++] = 0;
      apdu[apdulen++] = 0;
      apdu[apdulen++] = len;
      assert(apdulen <= apdu_buffer_size);
      memset(apdu + apdulen, 0, apdu_buffer_size - apdulen);
      resultlen = result_buffer_size;
      rc = send_apdu(slot, apdu, apdulen, result, &resultlen, NULL);
      if (rc || resultlen < 2) {
        log_error("apdu_send_simple(%d) for get response failed: %s\n", slot,
                  apdu_strerror(rc));
        unlock_slot(slot);
        xfree(result_buffer);
        return rc ? rc : SW_HOST_INCOMPLETE_CARD_RESPONSE;
      }
      sw = (result[resultlen - 2] << 8) | result[resultlen - 1];
      resultlen -= 2;
      if (DBG_CARD_IO) {
        log_debug("     more: sw=%04X  datalen=%d\n", sw,
                  (unsigned int)resultlen);
        if (!retbuf && (sw == SW_SUCCESS || (sw & 0xff00) == SW_MORE_DATA))
          log_printhex("     dump: ", result, resultlen);
      }

      if ((sw & 0xff00) == SW_MORE_DATA || sw == SW_SUCCESS ||
          sw == SW_EOF_REACHED) {
        if (retbuf && resultlen) {
          if (p - *retbuf + resultlen > bufsize) {
            bufsize += resultlen > 4096 ? resultlen : 4096;
            tmp = (unsigned char *)xtryrealloc(*retbuf, bufsize);
            if (!tmp) {
              unlock_slot(slot);
              xfree(result_buffer);
              return SW_HOST_OUT_OF_CORE;
            }
            p = tmp + (p - *retbuf);
            *retbuf = tmp;
          }
          memcpy(p, result, resultlen);
          p += resultlen;
        }
      } else
        log_info(
            "apdu_send_simple(%d) "
            "got unexpected status %04X from get response\n",
            slot, sw);
    } while ((sw & 0xff00) == SW_MORE_DATA);

    if (retbuf) {
      *retbuflen = p - *retbuf;
      tmp = (unsigned char *)xtryrealloc(*retbuf, *retbuflen);
      if (tmp) *retbuf = tmp;
    }
  }

  unlock_slot(slot);
  xfree(result_buffer);

  if (DBG_CARD_IO && retbuf && sw == SW_SUCCESS)
    log_printhex("      dump: ", *retbuf, *retbuflen);

  return sw;
}

/* Send an APDU to the card in SLOT.  The APDU is created from all
   given parameters: KLASSE, INS, P0, P1, LC, DATA, LE.  A value of -1
   for LC won't sent this field and the data field; in this case DATA
   must also be passed as NULL.  If EXTENDED_MODE is not 0 command
   chaining or extended length will be used; see send_le for details.
   The return value is the status word or -1 for an invalid SLOT or
   other non card related error.  If RETBUF is not NULL, it will
   receive an allocated buffer with the returned data.  The length of
   that data will be put into *RETBUFLEN.  The caller is responsible
   for releasing the buffer even in case of errors.  */
int apdu_send_le(int slot, int extended_mode, int klasse, int ins, int p0,
                 int p1, int lc, const char *data, int le,
                 unsigned char **retbuf, size_t *retbuflen) {
  return send_le(slot, klasse, ins, p0, p1, lc, data, le, retbuf, retbuflen,
                 NULL, extended_mode);
}

/* Send an APDU to the card in SLOT.  The APDU is created from all
   given parameters: KLASSE, INS, P0, P1, LC, DATA.  A value of -1 for
   LC won't sent this field and the data field; in this case DATA must
   also be passed as NULL.  If EXTENDED_MODE is not 0 command chaining
   or extended length will be used; see send_le for details.  The
   return value is the status word or -1 for an invalid SLOT or other
   non card related error.  If RETBUF is not NULL, it will receive an
   allocated buffer with the returned data.  The length of that data
   will be put into *RETBUFLEN.  The caller is responsible for
   releasing the buffer even in case of errors.  */
int apdu_send(int slot, int extended_mode, int klasse, int ins, int p0, int p1,
              int lc, const char *data, unsigned char **retbuf,
              size_t *retbuflen) {
  return send_le(slot, klasse, ins, p0, p1, lc, data, 256, retbuf, retbuflen,
                 NULL, extended_mode);
}

/* Send an APDU to the card in SLOT.  The APDU is created from all
   given parameters: KLASSE, INS, P0, P1, LC, DATA.  A value of -1 for
   LC won't sent this field and the data field; in this case DATA must
   also be passed as NULL.  If EXTENDED_MODE is not 0 command chaining
   or extended length will be used; see send_le for details.  The
   return value is the status word or -1 for an invalid SLOT or other
   non card related error.  No data will be returned.  */
int apdu_send_simple(int slot, int extended_mode, int klasse, int ins, int p0,
                     int p1, int lc, const char *data) {
  return send_le(slot, klasse, ins, p0, p1, lc, data, -1, NULL, NULL, NULL,
                 extended_mode);
}

/* This is a more generic version of the apdu sending routine.  It
   takes an already formatted APDU in APDUDATA or length APDUDATALEN
   and returns with an APDU including the status word.  With
   HANDLE_MORE set to true this function will handle the MORE DATA
   status and return all APDUs concatenated with one status word at
   the end.  If EXTENDED_LENGTH is != 0 extended lengths are allowed
   with a max. result data length of EXTENDED_LENGTH bytes.  The
   function does not return a regular status word but 0 on success.
   If the slot is locked, the function returns immediately with an
   error.  */
int apdu_send_direct(int slot, size_t extended_length,
                     const unsigned char *apdudata, size_t apdudatalen,
                     int handle_more, unsigned char **retbuf,
                     size_t *retbuflen) {
#define SHORT_RESULT_BUFFER_SIZE 258
  unsigned char short_result_buffer[SHORT_RESULT_BUFFER_SIZE + 10];
  unsigned char *result_buffer = NULL;
  size_t result_buffer_size;
  unsigned char *result;
  size_t resultlen;
  unsigned char short_apdu_buffer[5 + 256 + 10];
  unsigned char *apdu_buffer = NULL;
  unsigned char *apdu;
  size_t apdulen;
  int sw;
  long rc; /* we need a long here due to PC/SC. */
  int klasse;

  if (slot < 0 || slot >= MAX_READER || !reader_table[slot].used)
    return SW_HOST_NO_DRIVER;

  if (apdudatalen > 65535) return SW_HOST_INV_VALUE;

  if (apdudatalen > sizeof short_apdu_buffer - 5) {
    apdu_buffer = (unsigned char *)xtrymalloc(apdudatalen + 5);
    if (!apdu_buffer) return SW_HOST_OUT_OF_CORE;
    apdu = apdu_buffer;
  } else {
    apdu = short_apdu_buffer;
  }
  apdulen = apdudatalen;
  memcpy(apdu, apdudata, apdudatalen);
  klasse = apdulen ? *apdu : 0;

  if (extended_length >= 256 && extended_length <= 65536) {
    result_buffer_size = extended_length;
    result_buffer = (unsigned char *)xtrymalloc(result_buffer_size + 10);
    if (!result_buffer) {
      xfree(apdu_buffer);
      return SW_HOST_OUT_OF_CORE;
    }
    result = result_buffer;
  } else {
    result_buffer_size = SHORT_RESULT_BUFFER_SIZE;
    result = short_result_buffer;
  }
#undef SHORT_RESULT_BUFFER_SIZE

  if ((sw = trylock_slot(slot))) {
    xfree(apdu_buffer);
    xfree(result_buffer);
    return sw;
  }

  resultlen = result_buffer_size;
  rc = send_apdu(slot, apdu, apdulen, result, &resultlen, NULL);
  xfree(apdu_buffer);
  apdu_buffer = NULL;
  if (rc || resultlen < 2) {
    log_error("apdu_send_direct(%d) failed: %s\n", slot, apdu_strerror(rc));
    unlock_slot(slot);
    xfree(result_buffer);
    return rc ? rc : SW_HOST_INCOMPLETE_CARD_RESPONSE;
  }
  sw = (result[resultlen - 2] << 8) | result[resultlen - 1];
  /* Store away the returned data but strip the statusword. */
  resultlen -= 2;
  if (DBG_CARD_IO) {
    log_debug(" response: sw=%04X  datalen=%d\n", sw, (unsigned int)resultlen);
    if (!retbuf && (sw == SW_SUCCESS || (sw & 0xff00) == SW_MORE_DATA))
      log_printhex("     dump: ", result, resultlen);
  }

  if (handle_more && (sw & 0xff00) == SW_MORE_DATA) {
    unsigned char *p = NULL, *tmp;
    size_t bufsize = 4096;

    /* It is likely that we need to return much more data, so we
       start off with a large buffer. */
    if (retbuf) {
      *retbuf = p = (unsigned char *)xtrymalloc(bufsize + 2);
      if (!*retbuf) {
        unlock_slot(slot);
        xfree(result_buffer);
        return SW_HOST_OUT_OF_CORE;
      }
      assert(resultlen < bufsize);
      memcpy(p, result, resultlen);
      p += resultlen;
    }

    do {
      int len = (sw & 0x00ff);

      if (DBG_CARD_IO)
        log_debug("apdu_send_direct(%d): %d more bytes available\n", slot, len);
      apdu = short_apdu_buffer;
      apdulen = 0;
      apdu[apdulen++] = klasse;
      apdu[apdulen++] = 0xC0;
      apdu[apdulen++] = 0;
      apdu[apdulen++] = 0;
      apdu[apdulen++] = len;
      memset(apdu + apdulen, 0, sizeof(short_apdu_buffer) - apdulen);
      resultlen = result_buffer_size;
      rc = send_apdu(slot, apdu, apdulen, result, &resultlen, NULL);
      if (rc || resultlen < 2) {
        log_error("apdu_send_direct(%d) for get response failed: %s\n", slot,
                  apdu_strerror(rc));
        unlock_slot(slot);
        xfree(result_buffer);
        return rc ? rc : SW_HOST_INCOMPLETE_CARD_RESPONSE;
      }
      sw = (result[resultlen - 2] << 8) | result[resultlen - 1];
      resultlen -= 2;
      if (DBG_CARD_IO) {
        log_debug("     more: sw=%04X  datalen=%d\n", sw,
                  (unsigned int)resultlen);
        if (!retbuf && (sw == SW_SUCCESS || (sw & 0xff00) == SW_MORE_DATA))
          log_printhex("     dump: ", result, resultlen);
      }

      if ((sw & 0xff00) == SW_MORE_DATA || sw == SW_SUCCESS ||
          sw == SW_EOF_REACHED) {
        if (retbuf && resultlen) {
          if (p - *retbuf + resultlen > bufsize) {
            bufsize += resultlen > 4096 ? resultlen : 4096;
            tmp = (unsigned char *)xtryrealloc(*retbuf, bufsize + 2);
            if (!tmp) {
              unlock_slot(slot);
              xfree(result_buffer);
              return SW_HOST_OUT_OF_CORE;
            }
            p = tmp + (p - *retbuf);
            *retbuf = tmp;
          }
          memcpy(p, result, resultlen);
          p += resultlen;
        }
      } else
        log_info(
            "apdu_send_direct(%d) "
            "got unexpected status %04X from get response\n",
            slot, sw);
    } while ((sw & 0xff00) == SW_MORE_DATA);

    if (retbuf) {
      *retbuflen = p - *retbuf;
      tmp = (unsigned char *)xtryrealloc(*retbuf, *retbuflen + 2);
      if (tmp) *retbuf = tmp;
    }
  } else {
    if (retbuf) {
      *retbuf = (unsigned char *)xtrymalloc((resultlen ? resultlen : 1) + 2);
      if (!*retbuf) {
        unlock_slot(slot);
        xfree(result_buffer);
        return SW_HOST_OUT_OF_CORE;
      }
      *retbuflen = resultlen;
      memcpy(*retbuf, result, resultlen);
    }
  }

  unlock_slot(slot);
  xfree(result_buffer);

  /* Append the status word.  Note that we reserved the two extra
     bytes while allocating the buffer.  */
  if (retbuf) {
    (*retbuf)[(*retbuflen)++] = (sw >> 8);
    (*retbuf)[(*retbuflen)++] = sw;
  }

  if (DBG_CARD_IO && retbuf) log_printhex("      dump: ", *retbuf, *retbuflen);

  return 0;
}

const char *apdu_get_reader_name(int slot) {
  return reader_table[slot].rdrname;
}
