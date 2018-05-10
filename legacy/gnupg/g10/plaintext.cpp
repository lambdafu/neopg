/* plaintext.c -  process plaintext packets
 * Copyright (C) 1998, 1999, 2000, 2001, 2002, 2003, 2004, 2005,
 *               2006, 2009, 2010 Free Software Foundation, Inc.
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
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#ifdef HAVE_DOSISH_SYSTEM
#include <fcntl.h> /* for setmode() */
#endif

#include "../common/status.h"
#include "../common/ttyio.h"
#include "../common/util.h"
#include "filter.h"
#include "gpg.h"
#include "main.h"
#include "options.h"
#include "packet.h"

/* Get the output filename.  On success, the actual filename that is
   used is set in *FNAMEP and a filepointer is returned in *FP.

   DATA is the iobuf containing the input data.  We just use it to get
   the input file's filename.

   On success, the caller is responsible for calling xfree on *FNAMEP
   and calling es_close on *FPP.  */
gpg_error_t get_output_file(iobuf_t data, char **fnamep, estream_t *fpp) {
  gpg_error_t err = 0;
  char *fname = NULL;
  estream_t fp = NULL;
  int nooutput = 0;

  /* Create the filename as C string.  */
  if (opt.outfp) {
    fname = xtrystrdup("[FP]");
    if (!fname) {
      err = gpg_error_from_syserror();
      goto leave;
    }
  } else if (opt.outfile) {
    fname = xtrystrdup(opt.outfile->c_str());
    if (!fname) {
      err = gpg_error_from_syserror();
      goto leave;
    }
  } else {
    if (data) fname = make_outfile_name(iobuf_get_real_fname(data));
    if (!fname) fname = ask_outfile_name(NULL, 0);
    if (!fname) {
      err = GPG_ERR_GENERAL; /* Can't create file. */
      goto leave;
    }
  }

  if (nooutput)
    ;
  else if (opt.outfp) {
    fp = opt.outfp;
    es_set_binary(fp);
  } else if (iobuf_is_pipe_filename(fname) || !*fname) {
    /* No filename, or "-" given; write to the file descriptor or to
     * stdout. */
    int fd;
    char xname[64];

    fp = es_stdout;
    es_set_binary(fp);
  } else {
    while (!overwrite_filep(fname)) {
      char *tmp = ask_outfile_name(NULL, 0);
      if (!tmp || !*tmp) {
        xfree(tmp);
        /* FIXME: Below used to be GPG_ERR_CREATE_FILE */
        err = GPG_ERR_GENERAL;
        goto leave;
      }
      xfree(fname);
      fname = tmp;
    }
  }

  if (opt.outfp && is_secured_file(es_fileno(opt.outfp))) {
    err = GPG_ERR_EPERM;
    log_error(_("error creating '%s': %s\n"), fname, gpg_strerror(err));
    goto leave;
  } else if (fp || nooutput)
    ;
  else if (is_secured_filename(fname)) {
    gpg_err_set_errno(EPERM);
    err = gpg_error_from_syserror();
    log_error(_("error creating '%s': %s\n"), fname, gpg_strerror(err));
    goto leave;
  } else if (!(fp = es_fopen(fname, "wb"))) {
    err = gpg_error_from_syserror();
    log_error(_("error creating '%s': %s\n"), fname, gpg_strerror(err));
    goto leave;
  }

leave:
  if (err) {
    if (fp && fp != es_stdout && fp != opt.outfp) es_fclose(fp);
    xfree(fname);
    return err;
  }

  *fnamep = fname;
  *fpp = fp;
  return 0;
}

/* Handle a plaintext packet.  If MFX is not NULL, update the MDs
 * Note: We should have used the filter stuff here, but we have to add
 * some easy mimic to set a read limit, so we calculate only the bytes
 * from the plaintext.  */
int handle_plaintext(PKT_plaintext *pt, md_filter_context_t *mfx, int nooutput,
                     int clearsig) {
  char *fname = NULL;
  estream_t fp = NULL;
  static off_t count = 0;
  int err = 0;
  int c;
  int convert;

  if (pt->mode == 't' || pt->mode == 'u' || pt->mode == 'm')
    convert = pt->mode;
  else
    convert = 0;

  /* Let people know what the plaintext info is. This allows the
     receiving program to try and do something different based on the
     format code (say, recode UTF-8 to local). */
  if (!nooutput && is_status_enabled()) {
    char status[50];

    /* Better make sure that stdout has been flushed in case the
       output will be written to it.  This is to make sure that no
       not-yet-flushed stuff will be written after the plaintext
       status message.  */
    es_fflush(es_stdout);

    snprintf(status, sizeof status, "%X ", (byte)pt->mode);
    write_status_text(STATUS_PLAINTEXT, status);

    if (!pt->is_partial) {
      snprintf(status, sizeof status, "%lu", (unsigned long)pt->len);
      write_status_text(STATUS_PLAINTEXT_LENGTH, status);
    }
  }

  if (!nooutput) {
    err = get_output_file(pt->buf, &fname, &fp);
    if (err) goto leave;
  }

  if (!pt->is_partial) {
    /* We have an actual length (which might be zero). */

    if (clearsig) {
      log_error("clearsig encountered while not expected\n");
      err = GPG_ERR_UNEXPECTED;
      goto leave;
    }

    if (convert) /* Text mode.  */
    {
      for (; pt->len; pt->len--) {
        if ((c = iobuf_get(pt->buf)) == -1) {
          err = gpg_error_from_syserror();
          log_error("problem reading source (%u bytes remaining)\n",
                    (unsigned)pt->len);
          goto leave;
        }
        if (mfx->md) gcry_md_putc(mfx->md, c);
#ifndef HAVE_DOSISH_SYSTEM
        /* Convert to native line ending. */
        /* fixme: this hack might be too simple */
        if (c == '\r' && convert != 'm') continue;
#endif
        if (fp) {
          if (opt.max_output && (++count) > opt.max_output) {
            log_error("error writing to '%s': %s\n", fname,
                      "exceeded --max-output limit\n");
            err = GPG_ERR_TOO_LARGE;
            goto leave;
          } else if (es_putc(c, fp) == EOF) {
            if (es_ferror(fp))
              err = gpg_error_from_syserror();
            else
              err = GPG_ERR_EOF;
            log_error("error writing to '%s': %s\n", fname, gpg_strerror(err));
            goto leave;
          }
        }
      }
    } else /* Binary mode.  */
    {
      byte *buffer = (byte *)xmalloc(32768);
      while (pt->len) {
        int len = pt->len > 32768 ? 32768 : pt->len;
        len = iobuf_read(pt->buf, buffer, len);
        if (len == -1) {
          err = gpg_error_from_syserror();
          log_error("problem reading source (%u bytes remaining)\n",
                    (unsigned)pt->len);
          xfree(buffer);
          goto leave;
        }
        if (mfx->md) gcry_md_write(mfx->md, buffer, len);
        if (fp) {
          if (opt.max_output && (count += len) > opt.max_output) {
            log_error("error writing to '%s': %s\n", fname,
                      "exceeded --max-output limit\n");
            err = GPG_ERR_TOO_LARGE;
            xfree(buffer);
            goto leave;
          } else if (es_fwrite(buffer, 1, len, fp) != len) {
            err = gpg_error_from_syserror();
            log_error("error writing to '%s': %s\n", fname, gpg_strerror(err));
            xfree(buffer);
            goto leave;
          }
        }
        pt->len -= len;
      }
      xfree(buffer);
    }
  } else if (!clearsig) {
    if (convert) { /* text mode */
      while ((c = iobuf_get(pt->buf)) != -1) {
        if (mfx->md) gcry_md_putc(mfx->md, c);
#ifndef HAVE_DOSISH_SYSTEM
        if (c == '\r' && convert != 'm')
          continue; /* fixme: this hack might be too simple */
#endif
        if (fp) {
          if (opt.max_output && (++count) > opt.max_output) {
            log_error("Error writing to '%s': %s\n", fname,
                      "exceeded --max-output limit\n");
            err = GPG_ERR_TOO_LARGE;
            goto leave;
          } else if (es_putc(c, fp) == EOF) {
            if (es_ferror(fp))
              err = gpg_error_from_syserror();
            else
              err = GPG_ERR_EOF;
            log_error("error writing to '%s': %s\n", fname, gpg_strerror(err));
            goto leave;
          }
        }
      }
    } else { /* binary mode */
      byte *buffer;
      int eof_seen = 0;

      buffer = (byte *)xtrymalloc(32768);
      if (!buffer) {
        err = gpg_error_from_syserror();
        goto leave;
      }

      while (!eof_seen) {
        /* Why do we check for len < 32768:
         * If we won't, we would practically read 2 EOFs but
         * the first one has already popped the block_filter
         * off and therefore we don't catch the boundary.
         * So, always assume EOF if iobuf_read returns less bytes
         * then requested */
        int len = iobuf_read(pt->buf, buffer, 32768);
        if (len == -1) break;
        if (len < 32768) eof_seen = 1;
        if (mfx->md) gcry_md_write(mfx->md, buffer, len);
        if (fp) {
          if (opt.max_output && (count += len) > opt.max_output) {
            log_error("error writing to '%s': %s\n", fname,
                      "exceeded --max-output limit\n");
            err = GPG_ERR_TOO_LARGE;
            xfree(buffer);
            goto leave;
          } else if (es_fwrite(buffer, 1, len, fp) != len) {
            err = gpg_error_from_syserror();
            log_error("error writing to '%s': %s\n", fname, gpg_strerror(err));
            xfree(buffer);
            goto leave;
          }
        }
      }
      xfree(buffer);
    }
    pt->buf = NULL;
  } else /* Clear text signature - don't hash the last CR,LF.   */
  {
    int state = 0;

    while ((c = iobuf_get(pt->buf)) != -1) {
      if (fp) {
        if (opt.max_output && (++count) > opt.max_output) {
          log_error("error writing to '%s': %s\n", fname,
                    "exceeded --max-output limit\n");
          err = GPG_ERR_TOO_LARGE;
          goto leave;
        } else if (es_putc(c, fp) == EOF) {
          err = gpg_error_from_syserror();
          log_error("error writing to '%s': %s\n", fname, gpg_strerror(err));
          goto leave;
        }
      }
      if (!mfx->md) continue;
      if (state == 2) {
        gcry_md_putc(mfx->md, '\r');
        gcry_md_putc(mfx->md, '\n');
        state = 0;
      }
      if (!state) {
        if (c == '\r')
          state = 1;
        else if (c == '\n')
          state = 2;
        else
          gcry_md_putc(mfx->md, c);
      } else if (state == 1) {
        if (c == '\n')
          state = 2;
        else {
          gcry_md_putc(mfx->md, '\r');
          if (c == '\r')
            state = 1;
          else {
            state = 0;
            gcry_md_putc(mfx->md, c);
          }
        }
      }
    }
    pt->buf = NULL;
  }

  if (fp && fp != es_stdout && fp != opt.outfp && es_fclose(fp)) {
    err = gpg_error_from_syserror();
    log_error("error closing '%s': %s\n", fname, gpg_strerror(err));
    fp = NULL;
    goto leave;
  }
  fp = NULL;

leave:
  /* Make sure that stdout gets flushed after the plaintext has been
     handled.  This is for extra security as we do a flush anyway
     before checking the signature.  */
  if (es_fflush(es_stdout)) {
    /* We need to check the return code to detect errors like disk
       full for short plaintexts.  See bug#1207.  Checking return
       values is a good idea in any case.  */
    if (!err) err = gpg_error_from_syserror();
    log_error("error flushing '%s': %s\n", "[stdout]", gpg_strerror(err));
  }

  if (fp && fp != es_stdout && fp != opt.outfp) es_fclose(fp);
  xfree(fname);
  return err;
}

static void do_hash(gcry_md_hd_t md, gcry_md_hd_t md2, IOBUF fp, int textmode) {
  text_filter_context_t tfx;
  int c;

  if (textmode) {
    memset(&tfx, 0, sizeof tfx);
    iobuf_push_filter(fp, text_filter, &tfx);
  }
  if (md2) { /* work around a strange behaviour in pgp2 */
    /* It seems that at least PGP5 converts a single CR to a CR,LF too */
    int lc = -1;
    while ((c = iobuf_get(fp)) != -1) {
      if (c == '\n' && lc == '\r')
        gcry_md_putc(md2, c);
      else if (c == '\n') {
        gcry_md_putc(md2, '\r');
        gcry_md_putc(md2, c);
      } else if (c != '\n' && lc == '\r') {
        gcry_md_putc(md2, '\n');
        gcry_md_putc(md2, c);
      } else
        gcry_md_putc(md2, c);

      if (md) gcry_md_putc(md, c);
      lc = c;
    }
  } else {
    while ((c = iobuf_get(fp)) != -1) {
      if (md) gcry_md_putc(md, c);
    }
  }
}

/****************
 * Ask for the detached datafile and calculate the digest from it.
 * INFILE is the name of the input file.
 */
int ask_for_detached_datafile(gcry_md_hd_t md, gcry_md_hd_t md2,
                              const char *inname, int textmode) {
  progress_filter_context_t *pfx;
  char *answer = NULL;
  IOBUF fp;
  int rc = 0;

  pfx = new_progress_context();
  fp = open_sigfile(inname, pfx); /* Open default file. */

  if (!fp && !opt.batch) {
    int any = 0;
    tty_printf(_("Detached signature.\n"));
    do {
      char *name;

      xfree(answer);
      tty_enable_completion(NULL);
      name = cpr_get("detached_signature.filename",
                     _("Please enter name of data file: "));
      tty_disable_completion();
      cpr_kill_prompt();
      answer = make_filename(name, (void *)NULL);
      xfree(name);

      if (any && !*answer) {
        rc = GPG_ERR_GENERAL; /*G10ERR_READ_FILE */
        goto leave;
      }
      fp = iobuf_open(answer);
      if (fp && is_secured_file(iobuf_get_fd(fp))) {
        iobuf_close(fp);
        fp = NULL;
        gpg_err_set_errno(EPERM);
      }
      if (!fp && errno == ENOENT) {
        tty_printf("No such file, try again or hit enter to quit.\n");
        any++;
      } else if (!fp) {
        rc = gpg_error_from_syserror();
        log_error(_("can't open '%s': %s\n"), answer, strerror(errno));
        goto leave;
      }
    } while (!fp);
  }

  if (!fp) {
    if (opt.verbose) log_info(_("reading stdin ...\n"));
    fp = iobuf_open(NULL);
    log_assert(fp);
  }
  do_hash(md, md2, fp, textmode);
  iobuf_close(fp);

leave:
  xfree(answer);
  release_progress_context(pfx);
  return rc;
}

/* Hash the given files and append the hash to hash contexts MD and
 * MD2.  If FILES is NULL, stdin is hashed.  */
int hash_datafiles(gcry_md_hd_t md, gcry_md_hd_t md2,
                   const tao::optional<std::vector<std::string>> &files,
                   const char *sigfilename, int textmode) {
  progress_filter_context_t *pfx;
  IOBUF fp;

  pfx = new_progress_context();

  if (!files) {
    /* Check whether we can open the signed material.  We avoid
       trying to open a file if run in batch mode.  This assumed
       data file for a sig file feature is just a convenience thing
       for the command line and the user needs to read possible
       warning messages. */
    if (!opt.batch) {
      fp = open_sigfile(sigfilename, pfx);
      if (fp) {
        do_hash(md, md2, fp, textmode);
        iobuf_close(fp);
        release_progress_context(pfx);
        return 0;
      }
    }
    log_error(_("no signed data\n"));
    release_progress_context(pfx);
    return GPG_ERR_NO_DATA;
  }

  for (auto &sl : *files) {
    fp = iobuf_open(sl.c_str());
    if (fp && is_secured_file(iobuf_get_fd(fp))) {
      iobuf_close(fp);
      fp = NULL;
      gpg_err_set_errno(EPERM);
    }
    if (!fp) {
      int rc = gpg_error_from_syserror();
      log_error(_("can't open signed data '%s'\n"),
                print_fname_stdin(sl.c_str()));
      release_progress_context(pfx);
      return rc;
    }
    handle_progress(pfx, fp, sl.c_str());
    do_hash(md, md2, fp, textmode);
    iobuf_close(fp);
  }

  release_progress_context(pfx);
  return 0;
}

/* Hash the data from file descriptor DATA_FD and append the hash to hash
   contexts MD and MD2.  */
int hash_datafile_by_fd(gcry_md_hd_t md, gcry_md_hd_t md2, int data_fd,
                        int textmode) {
  progress_filter_context_t *pfx = new_progress_context();
  iobuf_t fp;

  if (is_secured_file(data_fd)) {
    fp = NULL;
    gpg_err_set_errno(EPERM);
  } else
    fp = iobuf_fdopen_nc(data_fd, "rb");

  if (!fp) {
    int rc = gpg_error_from_syserror();
    log_error(_("can't open signed data fd=%d: %s\n"), data_fd,
              strerror(errno));
    release_progress_context(pfx);
    return rc;
  }

  handle_progress(pfx, fp, NULL);

  do_hash(md, md2, fp, textmode);

  iobuf_close(fp);

  release_progress_context(pfx);
  return 0;
}

/* Set up a plaintext packet with the appropriate filename.  If there
   is a --set-filename, use it (it's already UTF8).  If there is a
   regular filename, UTF8-ize it if necessary.  If there is no
   filenames at all, set the field empty. */

PKT_plaintext *setup_plaintext_name(const char *filename, IOBUF iobuf) {
  PKT_plaintext *pt;

  /* no filename */
  pt = (PKT_plaintext *)xmalloc(sizeof *pt);

  return pt;
}
