/* crlfetch.c
 *      Copyright (C) 2002 Klarälvdalens Datakonsult AB
 *      Copyright (C) 2003, 2004, 2005, 2006, 2007 g10 Code GmbH
 *
 * This file is part of DirMngr.
 *
 * DirMngr is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * DirMngr is distributed in the hope that it will be useful,
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

#include "crlfetch.h"
#include "dirmngr.h"
#include "http.h"
#include "misc.h"

/* For detecting armored CRLs received via HTTP (yes, such CRLS really
   exits, e.g. http://grid.fzk.de/ca/gridka-crl.pem at least in June
   2008) we need a context in the reader callback.  */
struct reader_cb_context_s {
  estream_t fp;              /* The stream used with the ksba reader.  */
  int checked : 1;           /* PEM/binary detection ahs been done.    */
  int is_pem : 1;            /* The file stream is PEM encoded.        */
  gpgrt_b64state_t b64state; /* The state used for Base64 decoding.    */
};

/* We need to associate a reader object with the reader callback
   context.  This table is used for it. */
struct file_reader_map_s {
  ksba_reader_t reader;
  struct reader_cb_context_s *cb_ctx;
};
#define MAX_FILE_READER 50
static struct file_reader_map_s file_reader_map[MAX_FILE_READER];

/* Associate FP with READER.  If the table is full wait until another
   thread has removed an entry.  */
static void register_file_reader(ksba_reader_t reader,
                                 struct reader_cb_context_s *cb_ctx) {
  int i;

  for (;;) {
    for (i = 0; i < MAX_FILE_READER; i++)
      if (!file_reader_map[i].reader) {
        file_reader_map[i].reader = reader;
        file_reader_map[i].cb_ctx = cb_ctx;
        return;
      }
    log_info(_("reader to file mapping table full - waiting\n"));
    gnupg_sleep(2);
  }
}

/* Scan the table for an entry matching READER, remove that entry and
   return the associated file pointer. */
static struct reader_cb_context_s *get_file_reader(ksba_reader_t reader) {
  struct reader_cb_context_s *cb_ctx = NULL;
  int i;

  for (i = 0; i < MAX_FILE_READER; i++)
    if (file_reader_map[i].reader == reader) {
      cb_ctx = file_reader_map[i].cb_ctx;
      file_reader_map[i].reader = NULL;
      file_reader_map[i].cb_ctx = NULL;
      break;
    }
  return cb_ctx;
}

static int my_es_read(void *opaque, char *buffer, size_t nbytes,
                      size_t *nread) {
  struct reader_cb_context_s *cb_ctx = (reader_cb_context_s *)opaque;
  int result;

  result = es_read(cb_ctx->fp, buffer, nbytes, nread);
  if (result) return result;
  /* Fixme we should check whether the semantics of es_read are okay
     and well defined.  I have some doubts.  */
  if (nbytes && !*nread && es_feof(cb_ctx->fp)) return GPG_ERR_EOF;
  if (!nread && es_ferror(cb_ctx->fp)) return GPG_ERR_EIO;

  if (!cb_ctx->checked && *nread) {
    int c = *(unsigned char *)buffer;

    cb_ctx->checked = 1;
    if (((c & 0xc0) >> 6) == 0 /* class: universal */
        && (c & 0x1f) == 16    /* sequence */
        && (c & 0x20) /* is constructed */)
      ; /* Binary data.  */
    else {
      cb_ctx->is_pem = 1;
      cb_ctx->b64state = gpgrt_b64dec_start("");
    }
  }
  if (cb_ctx->is_pem && *nread) {
    size_t nread2;

    if (gpgrt_b64dec_proc(cb_ctx->b64state, buffer, *nread, &nread2)) {
      /* EOF from decoder. */
      *nread = 0;
      result = GPG_ERR_EOF;
    } else
      *nread = nread2;
  }

  return result;
}

/* Fetch CRL from URL and return the entire CRL using new ksba reader
   object in READER. */
gpg_error_t crl_fetch(ctrl_t ctrl, const char *url, ksba_reader_t *reader) {
  gpg_error_t err;
  parsed_uri_t uri;
  char *free_this = NULL;
  int redirects_left = 2; /* We allow for 2 redirect levels.  */

  *reader = NULL;

  if (!url) return GPG_ERR_INV_ARG;

once_more:
  err = http_parse_uri(&uri, url, 0);
  http_release_parsed_uri(uri);
  if (err && !strncmp(url, "https:", 6)) {
    /* FIXME: We now support https.
     * Our HTTP code does not support TLS, thus we can't use this
     * scheme and it is frankly not useful for CRL retrieval anyway.
     * We resort to using http, assuming that the server also
     * provides plain http access.  */
    free_this = (char *)xtrymalloc(strlen(url) + 1);
    if (free_this) {
      strcpy(stpcpy(free_this, "http:"), url + 6);
      err = http_parse_uri(&uri, free_this, 0);
      http_release_parsed_uri(uri);
      if (!err) {
        log_info(_("using \"http\" instead of \"https\"\n"));
        url = free_this;
      }
    }
  }
  if (!err) /* Yes, our HTTP code groks that. */
  {
    http_t hd;
    std::vector<std::string> headers;
    if (opt.disable_http) {
      log_error(_("CRL access not possible due to disabled %s\n"), "HTTP");
      err = GPG_ERR_NOT_SUPPORTED;
    } else
      err = http_open_document(
          &hd, url, NULL, ((opt.honor_http_proxy ? HTTP_FLAG_TRY_PROXY : 0) |
                           (DBG_LOOKUP ? HTTP_FLAG_LOG_RESP : 0) |
                           (opt.disable_ipv4 ? HTTP_FLAG_IGNORE_IPv4 : 0) |
                           (opt.disable_ipv6 ? HTTP_FLAG_IGNORE_IPv6 : 0)),
          ctrl->http_proxy, NULL, NULL, headers);

    switch (err ? 99999 : http_get_status_code(hd)) {
      case 200: {
        estream_t fp = http_get_read_ptr(hd);
        struct reader_cb_context_s *cb_ctx;

        cb_ctx = (reader_cb_context_s *)xtrycalloc(1, sizeof *cb_ctx);
        if (!cb_ctx) err = gpg_error_from_syserror();
        if (!err) err = ksba_reader_new(reader);
        if (!err) {
          cb_ctx->fp = fp;
          err = ksba_reader_set_cb(*reader, &my_es_read, cb_ctx);
        }
        if (err) {
          log_error(_("error initializing reader object: %s\n"),
                    gpg_strerror(err));
          ksba_reader_release(*reader);
          *reader = NULL;
          http_close(hd, 0);
        } else {
          /* The ksba reader misses a user pointer thus we need
             to come up with our own way of associating a file
             pointer (or well the callback context) with the
             reader.  It is only required when closing the
             reader thus there is no performance issue doing it
             this way.  FIXME: We now have a close notification
             which might be used here. */
          register_file_reader(*reader, cb_ctx);
          http_close(hd, 1);
        }
      } break;

      case 301: /* Redirection (perm.). */
      case 302: /* Redirection (temp.). */
      {
        const char *s = http_get_header(hd, "Location");

        log_info(_("URL '%s' redirected to '%s' (%u)\n"), url, s ? s : "[none]",
                 http_get_status_code(hd));
        if (s && *s && redirects_left--) {
          xfree(free_this);
          url = NULL;
          free_this = xtrystrdup(s);
          if (!free_this)
            err = gpg_error_from_errno(errno);
          else {
            url = free_this;
            http_close(hd, 0);
            goto once_more;
          }
        } else
          err = GPG_ERR_NO_DATA;
        log_error(_("too many redirections\n")); /* Or no "Location". */
        http_close(hd, 0);
      } break;

      case 99999: /* Made up status code for error reporting.  */
        log_error(_("error retrieving '%s': %s\n"), url, gpg_strerror(err));
        break;

      default:
        log_error(_("error retrieving '%s': http status %u\n"), url,
                  http_get_status_code(hd));
        err = GPG_ERR_NO_DATA;
        http_close(hd, 0);
    }
  } else /* Let the LDAP code try other schemes. */
    err = GPG_ERR_NOT_SUPPORTED;

  xfree(free_this);
  return err;
}

/* Fetch CRL for ISSUER using a default server. Return the entire CRL
   as a newly opened stream returned in R_FP. */
gpg_error_t crl_fetch_default(ctrl_t ctrl, const char *issuer,
                              ksba_reader_t *reader) {
  (void)ctrl;
  (void)issuer;
  (void)reader;
  return GPG_ERR_NOT_IMPLEMENTED;
}

/* Fetch a CA certificate for DN using the default server.  This
 * function only initiates the fetch; fetch_next_cert must be used to
 * actually read the certificate; end_cert_fetch to end the
 * operation.  */
gpg_error_t ca_cert_fetch(ctrl_t ctrl, cert_fetch_context_t *context,
                          const char *dn) {
  (void)ctrl;
  (void)context;
  (void)dn;
  return GPG_ERR_NOT_IMPLEMENTED;
}

gpg_error_t start_cert_fetch(ctrl_t ctrl, cert_fetch_context_t *context,
                             const std::vector<std::string> &patterns) {
  (void)ctrl;
  (void)context;
  (void)patterns;
  return GPG_ERR_NOT_IMPLEMENTED;
}

gpg_error_t fetch_next_cert(cert_fetch_context_t context, unsigned char **value,
                            size_t *valuelen) {
  (void)context;
  (void)value;
  (void)valuelen;
  return GPG_ERR_NOT_IMPLEMENTED;
}

/* Fetch the next data from CONTEXT, assuming it is a certificate and return
 * it as a cert object in R_CERT.  */
gpg_error_t fetch_next_ksba_cert(cert_fetch_context_t context,
                                 ksba_cert_t *r_cert) {
  gpg_error_t err;
  unsigned char *value;
  size_t valuelen;
  ksba_cert_t cert;

  *r_cert = NULL;

  (void)context;
  return GPG_ERR_NOT_IMPLEMENTED;
}

void end_cert_fetch(cert_fetch_context_t context) { (void)context; }

/* Lookup a cert by it's URL.  */
gpg_error_t fetch_cert_by_url(ctrl_t ctrl, const char *url,
                              unsigned char **value, size_t *valuelen) {
  const unsigned char *cert_image;
  size_t cert_image_n;
  ksba_reader_t reader;
  ksba_cert_t cert;
  gpg_error_t err;

  *value = NULL;
  *valuelen = 0;
  cert_image = NULL;
  reader = NULL;
  cert = NULL;

  (void)ctrl;
  (void)url;
  return GPG_ERR_NOT_IMPLEMENTED;
}

/* This function is to be used to close the reader object.  In
   addition to running ksba_reader_release it also releases the LDAP
   or HTTP contexts associated with that reader.  */
void crl_close_reader(ksba_reader_t reader) {
  struct reader_cb_context_s *cb_ctx;

  if (!reader) return;

  /* Check whether this is a HTTP one. */
  cb_ctx = get_file_reader(reader);
  if (cb_ctx) {
    /* This is an HTTP context. */
    if (cb_ctx->fp) es_fclose(cb_ctx->fp);
    /* Release the base64 decoder state.  */
    if (cb_ctx->is_pem) gpgrt_b64dec_finish(cb_ctx->b64state);
    /* Release the callback context.  */
    xfree(cb_ctx);
  }

  /* Now get rid of the reader object. */
  ksba_reader_release(reader);
}
