#define _BSD_SOURCE 1
#define _GNU_SOURCE 1
#undef _XOPEN_SOURCE
#undef _POSIX_SOURCE
#undef _POSIX_C_SOURCE

/* dns-stuff.c - DNS related code including CERT RR (rfc-4398)
 * Copyright (C) 2003, 2005, 2006, 2009 Free Software Foundation, Inc.
 * Copyright (C) 2005, 2006, 2009, 2015. 2016 Werner Koch
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
#include <sys/types.h>
#ifdef HAVE_W32_SYSTEM
#define WIN32_LEAN_AND_MEAN
#ifdef HAVE_WINSOCK2_H
#include <winsock2.h>
#endif
#include <iphlpapi.h>
#include <windows.h>
#else
#if HAVE_SYSTEM_RESOLVER
#include <arpa/nameser.h>
#include <arpa/nameser_compat.h>
#include <netinet/in.h>
#include <resolv.h>
#endif
#include <netdb.h>
#endif
#ifdef HAVE_STAT
#include <sys/stat.h>
#endif
#include <string.h>
#include <unistd.h>

/* dns.c has a dns_p_free but it is not exported.  We use our own
 * wrapper here so that we do not accidentally use xfree which would
 * be wrong for dns.c allocated data.  */
#define dns_free(a) free((a))

#include <gpg-error.h>
#include "../common/host2net.h"
#include "../common/util.h"
#include "dns-stuff.h"

#define my_unprotect() \
  do {                 \
  } while (0)
#define my_protect() \
  do {               \
  } while (0)

/* We allow the use of 0 instead of AF_UNSPEC - check this assumption.  */
#if AF_UNSPEC != 0
#error AF_UNSPEC does not have the value 0
#endif

/* Windows does not support the AI_ADDRCONFIG flag - use zero instead.  */
#ifndef AI_ADDRCONFIG
#define AI_ADDRCONFIG 0
#endif

/* Not every installation has gotten around to supporting SRVs or
   CERTs yet... */
#ifndef T_SRV
#define T_SRV 33
#endif
#undef T_CERT
#define T_CERT 37

/* The standard SOCKS and TOR ports.  */
#define SOCKS_PORT 1080
#define TOR_PORT 9050
#define TOR_PORT2 9150 /* (Used by the Tor browser) */

/* The default nameserver used in Tor mode.  */
#define DEFAULT_NAMESERVER "8.8.8.8"

/* The default timeout in seconds for libdns requests.  */
#define DEFAULT_TIMEOUT 30

#define RESOLV_CONF_NAME "/etc/resolv.conf"

/* Two flags to enable verbose and debug mode.  */
static int opt_verbose;
static int opt_debug;

/* The timeout in seconds for libdns requests.  */
static int opt_timeout;

/* The flag to disable IPv4 access - right now this only skips
 * returned A records.  */
static int opt_disable_ipv4;

/* The flag to disable IPv6 access - right now this only skips
 * returned AAAA records.  */
static int opt_disable_ipv6;

/* If set force the use of the standard resolver.  */
static int standard_resolver;

/* If set use recursive resolver when available. */
static int recursive_resolver;

/* Calling this function with YES set to True forces the use of the
 * standard resolver even if dirmngr has been built with support for
 * an alternative resolver.  */
void enable_standard_resolver(int yes) { standard_resolver = yes; }

/* Return true if the standard resolver is used.  */
int standard_resolver_p(void) { return standard_resolver; }

/* Calling this function with YES switches libdns into recursive mode.
 * It has no effect on the standard resolver.  */
void enable_recursive_resolver(int yes) { recursive_resolver = yes; }

/* Return true iff the recursive resolver is used.  */
int recursive_resolver_p(void) { return 0; }

/* Set verbosity and debug mode for this module. */
void set_dns_verbose(int verbose, int debug) {
  opt_verbose = verbose;
  opt_debug = debug;
}

/* Set the Disable-IPv4 flag so that the name resolver does not return
 * A addresses.  */
void set_dns_disable_ipv4(int yes) { opt_disable_ipv4 = !!yes; }

/* Set the Disable-IPv6 flag so that the name resolver does not return
 * AAAA addresses.  */
void set_dns_disable_ipv6(int yes) { opt_disable_ipv6 = !!yes; }

/* Set the timeout for libdns requests to SECONDS.  A value of 0 sets
 * the default timeout and values are capped at 10 minutes.  */
void set_dns_timeout(int seconds) {
  if (!seconds)
    seconds = DEFAULT_TIMEOUT;
  else if (seconds < 1)
    seconds = 1;
  else if (seconds > 600)
    seconds = 600;

  opt_timeout = seconds;
}

/* Free an addressinfo linked list as returned by resolve_dns_name.  */
void free_dns_addrinfo(dns_addrinfo_t ai) {
  while (ai) {
    dns_addrinfo_t next = ai->next;
    xfree(ai);
    ai = next;
  }
}

#ifndef HAVE_W32_SYSTEM
/* Return H_ERRNO mapped to a gpg-error code.  Will never return 0. */
static gpg_error_t get_h_errno_as_gpg_error(void) {
  gpg_error_t ec;

  switch (h_errno) {
    case HOST_NOT_FOUND:
      ec = GPG_ERR_NO_NAME;
      break;
    case TRY_AGAIN:
      ec = GPG_ERR_TRY_LATER;
      break;
    case NO_RECOVERY:
      ec = GPG_ERR_SERVER_FAILED;
      break;
    case NO_DATA:
      ec = GPG_ERR_NO_DATA;
      break;
    default:
      ec = GPG_ERR_UNKNOWN_ERRNO;
      break;
  }
  return ec;
}
#endif /*!HAVE_W32_SYSTEM*/

static gpg_error_t map_eai_to_gpg_error(int ec) {
  gpg_error_t err;

  switch (ec) {
    case EAI_AGAIN:
      err = GPG_ERR_EAGAIN;
      break;
    case EAI_BADFLAGS:
      err = GPG_ERR_INV_FLAG;
      break;
    case EAI_FAIL:
      err = GPG_ERR_SERVER_FAILED;
      break;
    case EAI_MEMORY:
      err = GPG_ERR_ENOMEM;
      break;
#ifdef EAI_NODATA
    case EAI_NODATA:
      err = GPG_ERR_NO_DATA;
      break;
#endif
    case EAI_NONAME:
      err = GPG_ERR_NO_NAME;
      break;
    case EAI_SERVICE:
      err = GPG_ERR_NOT_SUPPORTED;
      break;
    case EAI_FAMILY:
      err = GPG_ERR_EAFNOSUPPORT;
      break;
    case EAI_SOCKTYPE:
      err = GPG_ERR_ESOCKTNOSUPPORT;
      break;
#ifndef HAVE_W32_SYSTEM
#ifdef EAI_ADDRFAMILY
    case EAI_ADDRFAMILY:
      err = GPG_ERR_EADDRNOTAVAIL;
      break;
#endif
    case EAI_SYSTEM:
      err = gpg_error_from_syserror();
      break;
#endif
    default:
      err = GPG_ERR_UNKNOWN_ERRNO;
      break;
  }
  return err;
}

/* SIGHUP action handler for this module.  With FORCE set objects are
 * all immediately released. */
void reload_dns_stuff(int force) {
#ifdef USE_LIBDNS
  if (force) {
    libdns_deinit();
    libdns_reinit_pending = 0;
  } else {
    libdns_reinit_pending = 1;
    libdns_tor_port = 0; /* Start again with the default port.  */
  }
#else
  (void)force;
#endif
}

/* Resolve a name using the standard system function.  */
static gpg_error_t resolve_name_standard(const char *name, unsigned short port,
                                         int want_family, int want_socktype,
                                         dns_addrinfo_t *r_dai,
                                         char **r_canonname) {
  gpg_error_t err = 0;
  dns_addrinfo_t daihead = NULL;
  dns_addrinfo_t dai;
  struct addrinfo *aibuf = NULL;
  struct addrinfo hints, *ai;
  char portstr[21];
  int ret;

  *r_dai = NULL;
  if (r_canonname) *r_canonname = NULL;

  memset(&hints, 0, sizeof hints);
  hints.ai_family = want_family;
  hints.ai_socktype = want_socktype;
  hints.ai_flags = AI_ADDRCONFIG;
  if (r_canonname) hints.ai_flags |= AI_CANONNAME;
  if (is_ip_address(name)) hints.ai_flags |= AI_NUMERICHOST;

  if (port)
    snprintf(portstr, sizeof portstr, "%hu", port);
  else
    *portstr = 0;

  /* We can't use the AI_IDN flag because that does the conversion
     using the current locale.  However, GnuPG always used UTF-8.  To
     support IDN we would need to make use of the libidn API.  */
  ret = getaddrinfo(name, *portstr ? portstr : NULL, &hints, &aibuf);
  if (ret) {
    aibuf = NULL;
    err = map_eai_to_gpg_error(ret);
    if (err == GPG_ERR_NO_NAME) {
      /* There seems to be a bug in the glibc getaddrinfo function
         if the CNAME points to a long list of A and AAAA records
         in which case the function return NO_NAME.  Let's do the
         CNAME redirection again.  */
      char *cname;

      if (get_dns_cname(name, &cname)) goto leave; /* Still no success.  */

      ret = getaddrinfo(cname, *portstr ? portstr : NULL, &hints, &aibuf);
      xfree(cname);
      if (ret) {
        aibuf = NULL;
        err = map_eai_to_gpg_error(ret);
        goto leave;
      }
      err = 0; /* Yep, now it worked.  */
    } else
      goto leave;
  }

  if (r_canonname && aibuf && aibuf->ai_canonname) {
    *r_canonname = xtrystrdup(aibuf->ai_canonname);
    if (!*r_canonname) {
      err = gpg_error_from_syserror();
      goto leave;
    }
  }

  for (ai = aibuf; ai; ai = ai->ai_next) {
    if (ai->ai_family != AF_INET6 && ai->ai_family != AF_INET) continue;
    if (opt_disable_ipv4 && ai->ai_family == AF_INET) continue;
    if (opt_disable_ipv6 && ai->ai_family == AF_INET6) continue;

    dai = (dns_addrinfo_t)xtrymalloc(sizeof *dai);
    dai->family = ai->ai_family;
    dai->socktype = ai->ai_socktype;
    dai->protocol = ai->ai_protocol;
    dai->addrlen = ai->ai_addrlen;
    memcpy(dai->addr, ai->ai_addr, ai->ai_addrlen);
    dai->next = daihead;
    daihead = dai;
  }

leave:
  if (aibuf) freeaddrinfo(aibuf);
  if (err) {
    if (r_canonname) {
      xfree(*r_canonname);
      *r_canonname = NULL;
    }
    free_dns_addrinfo(daihead);
  } else
    *r_dai = daihead;
  return err;
}

/* This a wrapper around getaddrinfo with slightly different semantics.
   NAME is the name to resolve.
   PORT is the requested port or 0.
   WANT_FAMILY is either 0 (AF_UNSPEC), AF_INET6, or AF_INET4.
   WANT_SOCKETTYPE is either SOCK_STREAM or SOCK_DGRAM.

   On success the result is stored in a linked list with the head
   stored at the address R_AI; the caller must call gpg_addrinfo_free
   on this.  If R_CANONNAME is not NULL the official name of the host
   is stored there as a malloced string; if that name is not available
   NULL is stored.  */
gpg_error_t resolve_dns_name(const char *name, unsigned short port,
                             int want_family, int want_socktype,
                             dns_addrinfo_t *r_ai, char **r_canonname) {
  gpg_error_t err;

  err = resolve_name_standard(name, port, want_family, want_socktype, r_ai,
                              r_canonname);
  if (opt_debug)
    log_debug("dns: resolve_dns_name(%s): %s\n", name, gpg_strerror(err));
  return err;
}

/* Resolve an address using the standard system function.  */
static gpg_error_t resolve_addr_standard(const struct sockaddr_storage *addr,
                                         int addrlen, unsigned int flags,
                                         char **r_name) {
  gpg_error_t err;
  int ec;
  char *buffer, *p;
  int buflen;

  *r_name = NULL;

  buflen = NI_MAXHOST;
  buffer = (char *)xtrymalloc(buflen + 2 + 1);
  if (!buffer) return gpg_error_from_syserror();

  if ((flags & DNS_NUMERICHOST))
    ec = EAI_NONAME;
  else
    ec = getnameinfo((const struct sockaddr *)addr, addrlen, buffer, buflen,
                     NULL, 0, NI_NAMEREQD);

  if (!ec && *buffer == '[')
    ec = EAI_FAIL; /* A name may never start with a bracket.  */
  else if (ec == EAI_NONAME) {
    p = buffer;
    if (addr->ss_family == AF_INET6 && (flags & DNS_WITHBRACKET)) {
      *p++ = '[';
      buflen -= 2;
    }
    ec = getnameinfo((const struct sockaddr *)addr, addrlen, p, buflen, NULL, 0,
                     NI_NUMERICHOST);
    if (!ec && addr->ss_family == AF_INET6 && (flags & DNS_WITHBRACKET))
      strcat(buffer, "]");
  }

  if (ec)
    err = map_eai_to_gpg_error(ec);
  else {
    p = (char *)xtryrealloc(buffer, strlen(buffer) + 1);
    if (!p)
      err = gpg_error_from_syserror();
    else {
      buffer = p;
      err = 0;
    }
  }

  if (err)
    xfree(buffer);
  else
    *r_name = buffer;

  return err;
}

/* A wrapper around getnameinfo.  */
gpg_error_t resolve_dns_addr(const struct sockaddr_storage *addr, int addrlen,
                             unsigned int flags, char **r_name) {
  gpg_error_t err;

  err = resolve_addr_standard(addr, addrlen, flags, r_name);

  if (opt_debug) log_debug("dns: resolve_dns_addr(): %s\n", gpg_strerror(err));
  return err;
}

/* Check whether NAME is an IP address.  Returns a true if it is
 * either an IPv6 or a IPv4 numerical address.  The actual return
 * values can also be used to identify whether it is v4 or v6: The
 * true value will surprisingly be 4 for IPv4 and 6 for IPv6.  */
int is_ip_address(const char *name) {
  const char *s;
  int ndots, dblcol, n;

  if (*name == '[')
    return 6; /* yes: A legal DNS name may not contain this character;
                 this must be bracketed v6 address.  */
  if (*name == '.')
    return 0; /* No.  A leading dot is not a valid IP address.  */

  /* Check whether this is a v6 address.  */
  ndots = n = dblcol = 0;
  for (s = name; *s; s++) {
    if (*s == ':') {
      ndots++;
      if (s[1] == ':') {
        ndots++;
        if (dblcol) return 0; /* No: Only one "::" allowed.  */
        dblcol++;
        if (s[1]) s++;
      }
      n = 0;
    } else if (*s == '.')
      goto legacy;
    else if (!strchr("0123456789abcdefABCDEF", *s))
      return 0; /* No: Not a hex digit.  */
    else if (++n > 4)
      return 0; /* To many digits in a group.  */
  }
  if (ndots > 7)
    return 0; /* No: Too many colons.  */
  else if (ndots > 1)
    return 6; /* Yes: At least 2 colons indicate an v6 address.  */

legacy:
  /* Check whether it is legacy IP address.  */
  ndots = n = 0;
  for (s = name; *s; s++) {
    if (*s == '.') {
      if (s[1] == '.') return 0;       /* No:  Double dot. */
      if (atoi(s + 1) > 255) return 0; /* No:  Ipv4 byte value too large.  */
      ndots++;
      n = 0;
    } else if (!strchr("0123456789", *s))
      return 0; /* No: Not a digit.  */
    else if (++n > 3)
      return 0; /* No: More than 3 digits.  */
  }
  return (ndots == 3) ? 4 : 0;
}

/* Return true if NAME is an onion address.  */
int is_onion_address(const char *name) {
  size_t len;

  len = name ? strlen(name) : 0;
  if (len < 8 || strcmp(name + len - 6, ".onion")) return 0;
  /* Note that we require at least 2 characters before the suffix.  */
  return 1; /* Yes.  */
}

static int priosort(const void *a, const void *b) {
  const struct srventry *sa = (const srventry *)a, *sb = (const srventry *)b;
  if (sa->priority > sb->priority)
    return 1;
  else if (sa->priority < sb->priority)
    return -1;
  else
    return 0;
}

/* Standard resolver based helper for getsrv.  Note that it is
 * expected that NULL is stored at the address of LIST and 0 is stored
 * at the address of R_COUNT.  */
static gpg_error_t getsrv_standard(const char *name, struct srventry **list,
                                   unsigned int *r_count) {
#ifdef HAVE_SYSTEM_RESOLVER
  union {
    unsigned char ans[2048];
    HEADER header[1];
  } res;
  unsigned char *answer = res.ans;
  HEADER *header = res.header;
  unsigned char *pt, *emsg;
  int r, rc;
  u16 dlen;
  unsigned int srvcount = 0;
  u16 count;

  my_unprotect();
  r = res_query(name, C_IN, T_SRV, answer, sizeof res.ans);
  my_protect();
  if (r < 0) return get_h_errno_as_gpg_error();
  if (r < sizeof(HEADER)) return GPG_ERR_SERVER_FAILED;
  if (r > sizeof res.ans) return GPG_ERR_SYSTEM_BUG;
  if (header->rcode != NOERROR || !(count = ntohs(header->ancount)))
    return GPG_ERR_NO_NAME; /* Error or no record found.  */

  emsg = &answer[r];
  pt = &answer[sizeof(HEADER)];

  /* Skip over the query */
  rc = dn_skipname(pt, emsg);
  if (rc == -1) goto fail;

  pt += rc + QFIXEDSZ;

  while (count-- > 0 && pt < emsg) {
    struct srventry *srv;
    u16 type, klasse;
    struct srventry *newlist;

    newlist = (srventry *)xtryrealloc(*list,
                                      (srvcount + 1) * sizeof(struct srventry));
    if (!newlist) goto fail;
    *list = newlist;
    memset(&(*list)[srvcount], 0, sizeof(struct srventry));
    srv = &(*list)[srvcount];
    srvcount++;

    rc = dn_skipname(pt, emsg); /* The name we just queried for.  */
    if (rc == -1) goto fail;
    pt += rc;

    /* Truncated message? */
    if ((emsg - pt) < 16) goto fail;

    type = buf16_to_u16(pt);
    pt += 2;
    /* We asked for SRV and got something else !? */
    if (type != T_SRV) goto fail;

    klasse = buf16_to_u16(pt);
    pt += 2;
    /* We asked for IN and got something else !? */
    if (klasse != C_IN) goto fail;

    pt += 4; /* ttl */
    dlen = buf16_to_u16(pt);
    pt += 2;

    srv->priority = buf16_to_ushort(pt);
    pt += 2;
    srv->weight = buf16_to_ushort(pt);
    pt += 2;
    srv->port = buf16_to_ushort(pt);
    pt += 2;

    /* Get the name.  2782 doesn't allow name compression, but
     * dn_expand still works to pull the name out of the packet. */
    rc = dn_expand(answer, emsg, pt, srv->target, sizeof srv->target);
    if (rc == 1 && srv->target[0] == 0) /* "." */
    {
      xfree(*list);
      *list = NULL;
      return 0;
    }
    if (rc == -1) goto fail;
    pt += rc;
    /* Corrupt packet? */
    if (dlen != rc + 6) goto fail;
  }

  *r_count = srvcount;
  return 0;

fail:
  xfree(*list);
  *list = NULL;
  return GPG_ERR_GENERAL;

#else /*!HAVE_SYSTEM_RESOLVER*/

  (void)name;
  (void)list;
  (void)r_count;
  return GPG_ERR_NOT_SUPPORTED;

#endif /*!HAVE_SYSTEM_RESOLVER*/
}

/* Query a SRV record for SERVICE and PROTO for NAME.  If SERVICE is
 * NULL, NAME is expected to contain the full query name.  Note that
 * we do not return NONAME but simply store 0 at R_COUNT.  On error an
 * error code is returned and 0 stored at R_COUNT.  */
gpg_error_t get_dns_srv(const char *name, const char *service,
                        const char *proto, struct srventry **list,
                        unsigned int *r_count) {
  gpg_error_t err;
  char *namebuffer = NULL;
  unsigned int srvcount;
  int i;

  *list = NULL;
  *r_count = 0;
  srvcount = 0;

  /* If SERVICE is given construct the query from it and PROTO.  */
  if (service) {
    namebuffer =
        xtryasprintf("_%s._%s.%s", service, proto ? proto : "tcp", name);
    if (!namebuffer) {
      err = gpg_error_from_syserror();
      goto leave;
    }
    name = namebuffer;
  }

  err = getsrv_standard(name, list, &srvcount);

  if (err) {
    if (err == GPG_ERR_NO_NAME) err = 0;
    goto leave;
  }

  /* Now we have an array of all the srv records. */

  /* Order by priority */
  qsort(*list, srvcount, sizeof(struct srventry), priosort);

  /* For each priority, move the zero-weighted items first. */
  for (i = 0; i < srvcount; i++) {
    int j;

    for (j = i; j < srvcount && (*list)[i].priority == (*list)[j].priority;
         j++) {
      if ((*list)[j].weight == 0) {
        /* Swap j with i */
        if (j != i) {
          struct srventry temp;

          memcpy(&temp, &(*list)[j], sizeof(struct srventry));
          memcpy(&(*list)[j], &(*list)[i], sizeof(struct srventry));
          memcpy(&(*list)[i], &temp, sizeof(struct srventry));
        }

        break;
      }
    }
  }

  /* Run the RFC-2782 weighting algorithm.  We don't need very high
     quality randomness for this, so regular libc srand/rand is
     sufficient.  */

  {
    static int done;
    if (!done) {
      done = 1;
      srand(time(NULL) * getpid());
    }
  }

  for (i = 0; i < srvcount; i++) {
    int j;
    float prio_count = 0, chose;

    for (j = i; j < srvcount && (*list)[i].priority == (*list)[j].priority;
         j++) {
      prio_count += (*list)[j].weight;
      (*list)[j].run_count = prio_count;
    }

    chose = prio_count * rand() / RAND_MAX;

    for (j = i; j < srvcount && (*list)[i].priority == (*list)[j].priority;
         j++) {
      if (chose <= (*list)[j].run_count) {
        /* Swap j with i */
        if (j != i) {
          struct srventry temp;

          memcpy(&temp, &(*list)[j], sizeof(struct srventry));
          memcpy(&(*list)[j], &(*list)[i], sizeof(struct srventry));
          memcpy(&(*list)[i], &temp, sizeof(struct srventry));
        }
        break;
      }
    }
  }

leave:
  if (opt_debug) {
    if (err)
      log_debug("dns: getsrv(%s): %s\n", name, gpg_strerror(err));
    else
      log_debug("dns: getsrv(%s) -> %u records\n", name, srvcount);
  }
  if (!err) *r_count = srvcount;
  xfree(namebuffer);
  return err;
}

/* Standard resolver version of get_dns_cname.  */
gpg_error_t get_dns_cname_standard(const char *name, char **r_cname) {
#ifdef HAVE_SYSTEM_RESOLVER
  gpg_error_t err;
  int rc;
  union {
    unsigned char ans[2048];
    HEADER header[1];
  } res;
  unsigned char *answer = res.ans;
  HEADER *header = res.header;
  unsigned char *pt, *emsg;
  int r;
  char *cname;
  int cnamesize = 1025;
  u16 count;

  my_unprotect();
  r = res_query(name, C_IN, T_CERT, answer, sizeof res.ans);
  my_protect();
  if (r < 0) return get_h_errno_as_gpg_error();
  if (r < sizeof(HEADER)) return GPG_ERR_SERVER_FAILED;
  if (r > sizeof res.ans) return GPG_ERR_SYSTEM_BUG;
  if (header->rcode != NOERROR || !(count = ntohs(header->ancount)))
    return GPG_ERR_NO_NAME; /* Error or no record found.  */
  if (count != 1) return GPG_ERR_SERVER_FAILED;

  emsg = &answer[r];
  pt = &answer[sizeof(HEADER)];
  rc = dn_skipname(pt, emsg);
  if (rc == -1) return GPG_ERR_SERVER_FAILED;

  pt += rc + QFIXEDSZ;
  if (pt >= emsg) return GPG_ERR_SERVER_FAILED;

  rc = dn_skipname(pt, emsg);
  if (rc == -1) return GPG_ERR_SERVER_FAILED;
  pt += rc + 2 + 2 + 4;
  if (pt + 2 >= emsg) return GPG_ERR_SERVER_FAILED;
  pt += 2; /* Skip rdlen */

  cname = (char *)xtrymalloc(cnamesize);
  if (!cname) return gpg_error_from_syserror();

  rc = dn_expand(answer, emsg, pt, cname, cnamesize - 1);
  if (rc == -1) {
    xfree(cname);
    return GPG_ERR_SERVER_FAILED;
  }
  *r_cname = (char *)xtryrealloc(cname, strlen(cname) + 1);
  if (!*r_cname) {
    err = gpg_error_from_syserror();
    xfree(cname);
    return err;
  }
  return 0;

#else /*!HAVE_SYSTEM_RESOLVER*/

  (void)name;
  (void)r_cname;
  return GPG_ERR_NOT_IMPLEMENTED;

#endif /*!HAVE_SYSTEM_RESOLVER*/
}

gpg_error_t get_dns_cname(const char *name, char **r_cname) {
  gpg_error_t err;

  *r_cname = NULL;

  err = get_dns_cname_standard(name, r_cname);
  if (opt_debug)
    log_debug("get_dns_cname(%s)%s%s\n", name, err ? ": " : " -> ",
              err ? gpg_strerror(err) : *r_cname);
  return err;
}
