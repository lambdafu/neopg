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

#include <neopg/proto/http.h>

#include "crlfetch.h"

/* Fetch CRL from URL and return the entire CRL using new ksba reader
   object in READER. */
gpg_error_t crl_fetch(ctrl_t ctrl, const char *url, ksba_reader_t *reader) {
  gpg_error_t err;
  std::string response;
  *reader = NULL;

  if (!url) return GPG_ERR_INV_ARG;

  NeoPG::URI uri(url);
  if (uri.scheme != "http")
    /* Let the LDAP code try other schemes. FIXME: We removed LDAP
       support.  But curl can speak LDAP, so maybe use that.  */
    return GPG_ERR_NOT_SUPPORTED;

  if (opt.disable_http) {
    log_error(_("CRL access not possible due to disabled %s\n"), "HTTP");
    return GPG_ERR_NOT_SUPPORTED;
  }
  /* libcurl doesn't easily support disabling all DNS lookups.  */
  if (opt.disable_ipv4 && opt.disable_ipv6) {
    log_error(_("CRL access not possible due to disabled %s\n"),
              "ipv4 and ipv6");
    return GPG_ERR_NOT_SUPPORTED;
  }

  NeoPG::Http request;
  request.set_url(url).forbid_reuse().set_timeout(ctrl->timeout).no_cache();

  if (opt.http_proxy)
    request.set_proxy(opt.http_proxy);
  else
    request.default_proxy(opt.honor_http_proxy);

  if (opt.disable_ipv6)
    request.set_ipresolve(NeoPG::Http::Resolve::IPv4);
  else if (opt.disable_ipv4)
    request.set_ipresolve(NeoPG::Http::Resolve::IPv6);

  try {
    response = request.fetch();
  } catch (const std::runtime_error &e) {
    log_error(_("error retrieving '%s': %s\n"), url, e.what());
    return GPG_ERR_NO_DATA;
  }

  /* Check for PEM, such as http://grid.fzk.de/ca/gridka-crl.pem (2008-2017). */
  if (response.size()) {
    uint8_t c = response[0];
    if (((c & 0xc0) >> 6) == 0 /* class: universal */
        && (c & 0x1f) == 16    /* sequence */
        && (c & 0x20) /* is constructed */)
      ; /* Binary data.  */
    else {
      /* Decode PEM.  */
      gpgrt_b64state_t b64state;
      b64state = gpgrt_b64dec_start("");
      size_t new_size;
      gpgrt_b64dec_proc(b64state, (void *)response.data(), response.size(),
                        &new_size);
      gpgrt_b64dec_finish(b64state);
      response.resize(new_size);
    }
  }

  err = ksba_reader_new(reader);
  if (!err) {
    err = ksba_reader_set_mem(*reader, response.data(), response.size());
  }
  if (err) {
    log_error(_("error initializing reader object: %s\n"), gpg_strerror(err));
    ksba_reader_release(*reader);
    *reader = NULL;
  }
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
  if (!reader) return;

  /* Now get rid of the reader object. */
  ksba_reader_release(reader);
}
