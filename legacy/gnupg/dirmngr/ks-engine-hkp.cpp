/* ks-engine-hkp.c - HKP keyserver engine
 * Copyright (C) 2011, 2012 Free Software Foundation, Inc.
 * Copyright (C) 2011, 2012, 2014 Werner Koch
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

#include <boost/optional.hpp>

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef HAVE_W32_SYSTEM
#ifdef HAVE_WINSOCK2_H
#include <winsock2.h>
#endif
#include <windows.h>
#else /*!HAVE_W32_SYSTEM*/
#include <netdb.h>
#include <sys/socket.h>
#include <sys/types.h>
#endif /*!HAVE_W32_SYSTEM*/

#include <neopg/proto/http.h>

#include "../common/userids.h"
#include "dirmngr.h"
#include "dns-stuff.h"
#include "ks-engine.h"
#include "misc.h"

/* Substitutes for missing Mingw macro.  The EAI_SYSTEM mechanism
   seems not to be available (probably because there is only one set
   of error codes anyway).  For now we use WSAEINVAL. */
#ifndef EAI_OVERFLOW
#define EAI_OVERFLOW EAI_FAIL
#endif
#ifdef HAVE_W32_SYSTEM
#ifndef EAI_SYSTEM
#define EAI_SYSTEM WSAEINVAL
#endif
#endif

/* Number of seconds after a host is marked as resurrected.  */
#define RESURRECT_INTERVAL (3600 * 3) /* 3 hours */

/* To match the behaviour of our old gpgkeys helper code we escape
   more characters than actually needed. */
#define EXTRA_ESCAPE_CHARS "@!\"#$%&'()*+,-./:;<=>?[\\]^_{|}~"

/* How many redirections do we allow.  */
#define MAX_REDIRECTS 2

/* Number of retries done for a dead host etc.  */
#define SEND_REQUEST_RETRIES 3

enum ks_protocol { KS_PROTOCOL_HKP, KS_PROTOCOL_HKPS, KS_PROTOCOL_MAX };

/* Objects used to maintain information about hosts.  */
struct hostinfo_s;
typedef struct hostinfo_s *hostinfo_t;
struct hostinfo_s {
  time_t lastfail;  /* Time we tried to connect and failed.  */
  time_t lastused;  /* Time of last use.  */
  int *pool;        /* An array with indices into HOSTTABLE or NULL
                       if NAME is not a pool name.  */
  size_t pool_len;  /* Length of POOL.  */
  size_t pool_size; /* Allocated size of POOL.  */
#define MAX_POOL_SIZE 128
  int poolidx; /* Index into POOL with the used host.  -1 if not set.  */
  unsigned int v4 : 1;             /* Host supports AF_INET.  */
  unsigned int v6 : 1;             /* Host supports AF_INET6.  */
  unsigned int onion : 1;          /* NAME is an onion (Tor HS) address.  */
  unsigned int dead : 1;           /* Host is currently unresponsive.  */
  unsigned int iporname_valid : 1; /* The field IPORNAME below is valid */
                                   /* (but may be NULL) */
  unsigned int did_a_lookup : 1;   /* Have we done an A lookup yet?  */
  time_t died_at; /* The time the host was marked dead.  If this is
                     0 the host has been manually marked dead.  */
  char *cname;    /* Canonical name of the host.  Only set if this
                     is a pool or NAME has a numerical IP address.  */
  char *iporname; /* Numeric IP address or name for printing.  */
  unsigned short port[KS_PROTOCOL_MAX];
  /* The port used by the host for all protocols, 0
     if unknown.  */
  char name[1]; /* The hostname.  */
};

/* An array of hostinfo_t for all hosts requested by the caller or
   resolved from a pool name and its allocated size.*/
static hostinfo_t *hosttable;
static int hosttable_size;

/* The number of host slots we initially allocate for HOSTTABLE.  */
#define INITIAL_HOSTTABLE_SIZE 10

/* Create a new hostinfo object, fill in NAME and put it into
   HOSTTABLE.  Return the index into hosttable on success or -1 on
   error. */
static int create_new_hostinfo(const char *name) {
  hostinfo_t hi, *newtable;
  int newsize;
  int idx, rc;

  hi = (hostinfo_t)xtrymalloc(sizeof *hi + strlen(name));
  if (!hi) return -1;
  strcpy(hi->name, name);
  hi->pool = NULL;
  hi->pool_len = 0;
  hi->pool_size = 0;
  hi->poolidx = -1;
  hi->lastused = (time_t)(-1);
  hi->lastfail = (time_t)(-1);
  hi->v4 = 0;
  hi->v6 = 0;
  hi->onion = 0;
  hi->dead = 0;
  hi->did_a_lookup = 0;
  hi->iporname_valid = 0;
  hi->died_at = 0;
  hi->cname = NULL;
  hi->iporname = NULL;
  hi->port[KS_PROTOCOL_HKP] = 0;
  hi->port[KS_PROTOCOL_HKPS] = 0;

  /* Add it to the hosttable. */
  for (idx = 0; idx < hosttable_size; idx++)
    if (!hosttable[idx]) {
      hosttable[idx] = hi;
      return idx;
    }
  /* Need to extend the hosttable.  */
  newsize = hosttable_size + INITIAL_HOSTTABLE_SIZE;
  newtable = (hostinfo_s **)xtryrealloc(hosttable, newsize * sizeof *hosttable);
  if (!newtable) {
    xfree(hi);
    return -1;
  }
  hosttable = newtable;
  idx = hosttable_size;
  hosttable_size = newsize;
  rc = idx;
  hosttable[idx++] = hi;
  while (idx < hosttable_size) hosttable[idx++] = NULL;

  return rc;
}

/* Find the host NAME in our table.  Return the index into the
   hosttable or -1 if not found.  */
static int find_hostinfo(const char *name) {
  int idx;

  for (idx = 0; idx < hosttable_size; idx++)
    if (hosttable[idx] && !ascii_strcasecmp(hosttable[idx]->name, name))
      return idx;
  return -1;
}

static int sort_hostpool(const void *xa, const void *xb) {
  int a = *(int *)xa;
  int b = *(int *)xb;

  assert(a >= 0 && a < hosttable_size);
  assert(b >= 0 && b < hosttable_size);
  assert(hosttable[a]);
  assert(hosttable[b]);

  return ascii_strcasecmp(hosttable[a]->name, hosttable[b]->name);
}

/* Return true if the host with the hosttable index TBLIDX is in HI->pool.  */
static int host_in_pool_p(hostinfo_t hi, int tblidx) {
  int i, pidx;

  for (i = 0; i < hi->pool_len && (pidx = hi->pool[i]) != -1; i++)
    if (pidx == tblidx && hosttable[pidx]) return 1;
  return 0;
}

/* Select a random host.  Consult HI->pool which indices into the global
   hosttable.  Returns index into HI->pool or -1 if no host could be
   selected.  */
static int select_random_host(hostinfo_t hi) {
  int *tbl;
  size_t tblsize;
  int pidx, idx;

  /* We create a new table so that we randomly select only from
     currently alive hosts.  */
  for (idx = 0, tblsize = 0; idx < hi->pool_len && (pidx = hi->pool[idx]) != -1;
       idx++)
    if (hosttable[pidx] && !hosttable[pidx]->dead) tblsize++;
  if (!tblsize) return -1; /* No hosts.  */

  tbl = (int *)xtrymalloc(tblsize * sizeof *tbl);
  if (!tbl) return -1;
  for (idx = 0, tblsize = 0; idx < hi->pool_len && (pidx = hi->pool[idx]) != -1;
       idx++)
    if (hosttable[pidx] && !hosttable[pidx]->dead) tbl[tblsize++] = pidx;

  if (tblsize == 1) /* Save a get_uint_nonce.  */
    pidx = tbl[0];
  else
    pidx = tbl[get_uint_nonce() % tblsize];

  xfree(tbl);
  return pidx;
}

/* Figure out if a set of DNS records looks like a pool.  */
static int arecords_is_pool(dns_addrinfo_t aibuf) {
  dns_addrinfo_t ai;
  int n_v6, n_v4;

  n_v6 = n_v4 = 0;
  for (ai = aibuf; ai; ai = ai->next) {
    if (ai->family == AF_INET6)
      n_v6++;
    else if (ai->family == AF_INET)
      n_v4++;
  }

  return n_v6 > 1 || n_v4 > 1;
}

/* Add the host AI under the NAME into the HOSTTABLE.  If PORT is not
   zero, it specifies which port to use to talk to the host for
   PROTOCOL.  If NAME specifies a pool (as indicated by IS_POOL),
   update the given reference table accordingly.  */
static void add_host(const char *name, int is_pool, const dns_addrinfo_t ai,
                     enum ks_protocol protocol, unsigned short port) {
  gpg_error_t tmperr;
  char *tmphost;
  int idx, tmpidx;
  hostinfo_t host;
  int i;

  idx = find_hostinfo(name);
  host = hosttable[idx];

  if (is_pool) {
    /* For a pool immediately convert the address to a string.  */
    tmperr = resolve_dns_addr(ai->addr, ai->addrlen,
                              (DNS_NUMERICHOST | DNS_WITHBRACKET), &tmphost);
  } else if (!is_ip_address(name)) {
    /* This is a hostname.  Use the name as given without going
     * through resolve_dns_addr.  */
    tmphost = xtrystrdup(name);
    if (!tmphost)
      tmperr = gpg_error_from_syserror();
    else
      tmperr = 0;
  } else {
    /* Do a PTR lookup on AI.  If a name was not found the function
     * returns the numeric address (with brackets).  */
    tmperr = resolve_dns_addr(ai->addr, ai->addrlen, DNS_WITHBRACKET, &tmphost);
  }

  if (tmperr) {
    log_info("resolve_dns_addr failed while checking '%s': %s\n", name,
             gpg_strerror(tmperr));
  } else if (host->pool_len + 1 >= MAX_POOL_SIZE) {
    log_error(
        "resolve_dns_addr for '%s': '%s'"
        " [index table full - ignored]\n",
        name, tmphost);
  } else {
    if (!is_pool && is_ip_address(name)) /* Update the original entry.  */
      tmpidx = idx;
    else
      tmpidx = find_hostinfo(tmphost);
    log_info("resolve_dns_addr for '%s': '%s'%s\n", name, tmphost,
             tmpidx == -1 ? "" : " [already known]");

    if (tmpidx == -1) /* Create a new entry.  */
      tmpidx = create_new_hostinfo(tmphost);

    if (tmpidx == -1) {
      log_error("map_host for '%s' problem: %s - '%s' [ignored]\n", name,
                strerror(errno), tmphost);
    } else /* Set or update the entry. */
    {
      if (port) hosttable[tmpidx]->port[protocol] = port;

      if (ai->family == AF_INET6) {
        hosttable[tmpidx]->v6 = 1;
      } else if (ai->family == AF_INET) {
        hosttable[tmpidx]->v4 = 1;
      } else
        BUG();

      /* If we updated the main entry, we're done.  */
      if (idx == tmpidx) goto leave;

      /* If we updated an existing entry, we're done.  */
      for (i = 0; i < host->pool_len; i++)
        if (host->pool[i] == tmpidx) goto leave;

      /* Otherwise, we need to add it to the pool.  Check if there
         is space.  */
      if (host->pool_len + 1 > host->pool_size) {
        int *new_pool;
        size_t new_size;

        if (host->pool_size == 0)
          new_size = 4;
        else
          new_size = host->pool_size * 2;

        new_pool = (int *)xtryrealloc(host->pool, new_size * sizeof *new_pool);

        if (new_pool == NULL) goto leave;

        host->pool = new_pool;
        host->pool_size = new_size;
      }

      /* Finally, add it.  */
      log_assert(host->pool_len < host->pool_size);
      host->pool[host->pool_len++] = tmpidx;
    }
  }
leave:
  xfree(tmphost);
}

/* Sort the pool of the given hostinfo HI.  */
static void hostinfo_sort_pool(hostinfo_t hi) {
  qsort(hi->pool, hi->pool_len, sizeof *hi->pool, sort_hostpool);
}

/* Map the host name NAME to the actual to be used host name.  This
 * allows us to manage round robin DNS names.  We use our own strategy
 * to choose one of the hosts.  For example we skip those hosts which
 * failed for some time and we stick to one host for a time
 * independent of DNS retry times.  If FORCE_RESELECT is true a new
 * host is always selected.  The selected host is stored as a malloced
 * string at R_HOST; on error NULL is stored.  If we know the port
 * used by the selected host from a service record, a string
 * representation is written to R_PORTSTR, otherwise it is left
 * untouched.  If R_HTTPFLAGS is not NULL it will receive flags which
 * are to be passed to http_open.  If R_HTTPHOST is not NULL a
 * malloced name of the host is stored there; this might be different
 * from R_HOST in case it has been selected from a pool.  */
static gpg_error_t map_host(ctrl_t ctrl, const char *name, int force_reselect,
                            enum ks_protocol protocol, char **r_host,
                            char *r_portstr, unsigned int *r_httpflags,
                            char **r_httphost) {
  gpg_error_t err = 0;
  hostinfo_t hi;
  int idx;
  dns_addrinfo_t aibuf, ai;
  int is_pool;
  int new_hosts = 0;
  char *cname;

  *r_host = NULL;
  if (r_httpflags) *r_httpflags = 0;
  if (r_httphost) *r_httphost = NULL;

  /* No hostname means localhost.  */
  if (!name || !*name) {
    *r_host = xtrystrdup("localhost");
    return *r_host ? 0 : gpg_error_from_syserror();
  }

  /* See whether the host is in our table.  */
  idx = find_hostinfo(name);
  if (idx == -1) {
    idx = create_new_hostinfo(name);
    if (idx == -1) return gpg_error_from_syserror();
    hi = hosttable[idx];
    hi->onion = is_onion_address(name);
  } else
    hi = hosttable[idx];

  is_pool = hi->pool != NULL;

  if (!hi->did_a_lookup && !hi->onion) {
    /* Find all A records for this entry and put them into the pool
       list - if any.  */
    err = resolve_dns_name(name, 0, 0, SOCK_STREAM, &aibuf, &cname);
    if (err) {
      log_error("resolving '%s' failed: %s\n", name, gpg_strerror(err));
      err = 0;
    } else {
      /* First figure out whether this is a pool.  For a pool we
         use a different strategy than for a plain server: We use
         the canonical name of the pool as the virtual host along
         with the IP addresses.  If it is not a pool, we use the
         specified name. */
      if (!is_pool) is_pool = arecords_is_pool(aibuf);
      if (is_pool && cname) {
        hi->cname = cname;
        cname = NULL;
      }

      for (ai = aibuf; ai; ai = ai->next) {
        if (ai->family != AF_INET && ai->family != AF_INET6) continue;
        if (opt.disable_ipv4 && ai->family == AF_INET) continue;
        if (opt.disable_ipv6 && ai->family == AF_INET6) continue;
        dirmngr_tick(ctrl);

        add_host(name, is_pool, ai, (ks_protocol)(0), 0);
        new_hosts = 1;
      }

      hi->did_a_lookup = 1;
    }
    xfree(cname);
    free_dns_addrinfo(aibuf);
  }
  if (new_hosts) hostinfo_sort_pool(hi);

  if (hi->pool) {
    /* Deal with the pool name before selecting a host. */
    if (r_httphost) {
      *r_httphost = xtrystrdup(hi->cname ? hi->cname : hi->name);
      if (!*r_httphost) return gpg_error_from_syserror();
    }

    /* If the currently selected host is now marked dead, force a
       re-selection .  */
    if (force_reselect)
      hi->poolidx = -1;
    else if (hi->poolidx >= 0 && hi->poolidx < hosttable_size &&
             hosttable[hi->poolidx] && hosttable[hi->poolidx]->dead)
      hi->poolidx = -1;

    /* Select a host if needed.  */
    if (hi->poolidx == -1) {
      hi->poolidx = select_random_host(hi);
      if (hi->poolidx == -1) {
        log_error("no alive host found in pool '%s'\n", name);
        if (r_httphost) {
          xfree(*r_httphost);
          *r_httphost = NULL;
        }
        return GPG_ERR_NO_KEYSERVER;
      }
    }

    assert(hi->poolidx >= 0 && hi->poolidx < hosttable_size);
    hi = hosttable[hi->poolidx];
    assert(hi);
  } else if (r_httphost && is_ip_address(hi->name)) {
    /* This is a numerical IP address and not a pool.  We want to
     * find the canonical name so that it can be used in the HTTP
     * Host header.  Fixme: We should store that name in the
     * hosttable. */
    char *host;

    err = resolve_dns_name(hi->name, 0, 0, SOCK_STREAM, &aibuf, NULL);
    if (!err) {
      for (ai = aibuf; ai; ai = ai->next) {
        if ((!opt.disable_ipv6 && ai->family == AF_INET6) ||
            (!opt.disable_ipv4 && ai->family == AF_INET)) {
          err = resolve_dns_addr(ai->addr, ai->addrlen, 0, &host);
          if (!err) {
            /* Okay, we return the first found name.  */
            *r_httphost = host;
            break;
          }
        }
      }
    }
    free_dns_addrinfo(aibuf);
  }

  if (hi->dead) {
    log_error("host '%s' marked as dead\n", hi->name);
    if (r_httphost) {
      xfree(*r_httphost);
      *r_httphost = NULL;
    }
    return GPG_ERR_NO_KEYSERVER;
  }

#if 0
  if (r_httpflags) {
    /* If the hosttable does not indicate that a certain host
       supports IPv<N>, we explicit set the corresponding http
       flags.  The reason for this is that a host might be listed in
       a pool as not v6 only but actually support v6 when later
       the name is resolved by our http layer.  */
    if (!hi->v4) *r_httpflags |= HTTP_FLAG_IGNORE_IPv4;
    if (!hi->v6) *r_httpflags |= HTTP_FLAG_IGNORE_IPv6;
  }
#endif

  *r_host = xtrystrdup(hi->name);
  if (!*r_host) {
    err = gpg_error_from_syserror();
    if (r_httphost) {
      xfree(*r_httphost);
      *r_httphost = NULL;
    }
    return err;
  }
  if (hi->port[protocol])
    snprintf(r_portstr, 6 /* five digits and the sentinel */, "%hu",
             hi->port[protocol]);
  return 0;
}

/* Mark the host NAME as dead.  NAME may be given as an URL.  Returns
   true if a host was really marked as dead or was already marked dead
   (e.g. by a concurrent session).  */
static int mark_host_dead(const char *name) {
  const char *host;
  char *host_buffer = NULL;
  parsed_uri_t parsed_uri = NULL;
  int done = 0;

  if (name && *name && !http_parse_uri(&parsed_uri, name, 1)) {
    if (parsed_uri->v6lit) {
      host_buffer = strconcat("[", parsed_uri->host, "]", NULL);
      if (!host_buffer) log_error("out of core in mark_host_dead");
      host = host_buffer;
    } else
      host = parsed_uri->host;
  } else
    host = name;

  if (host && *host && strcmp(host, "localhost")) {
    hostinfo_t hi;
    int idx;

    idx = find_hostinfo(host);
    if (idx != -1) {
      hi = hosttable[idx];
      log_info("marking host '%s' as dead%s\n", hi->name,
               hi->dead ? " (again)" : "");
      hi->dead = 1;
      hi->died_at = gnupg_get_time();
      if (!hi->died_at) hi->died_at = 1;
      done = 1;
    }
  }

  http_release_parsed_uri(parsed_uri);
  xfree(host_buffer);
  return done;
}

/* Mark a host in the hosttable as dead or - if ALIVE is true - as
   alive.  */
gpg_error_t ks_hkp_mark_host(ctrl_t ctrl, const char *name, int alive) {
  gpg_error_t err = 0;
  hostinfo_t hi, hi2;
  int idx, idx2, idx3, n;

  if (!name || !*name || !strcmp(name, "localhost")) return 0;

  idx = find_hostinfo(name);
  if (idx == -1) return GPG_ERR_NOT_FOUND;

  hi = hosttable[idx];
  if (alive && hi->dead) {
    hi->dead = 0;
    err = ks_printf_help(ctrl, "marking '%s' as alive", name);
  } else if (!alive && !hi->dead) {
    hi->dead = 1;
    hi->died_at = 0; /* Manually set dead.  */
    err = ks_printf_help(ctrl, "marking '%s' as dead", name);
  }

  /* If the host is a pool mark all member hosts. */
  if (!err && hi->pool) {
    for (idx2 = 0; !err && idx2 < hi->pool_len && (n = hi->pool[idx2]) != -1;
         idx2++) {
      assert(n >= 0 && n < hosttable_size);

      if (!alive) {
        /* Do not mark a host from a pool dead if it is also a
           member in another pool.  */
        for (idx3 = 0; idx3 < hosttable_size; idx3++) {
          if (hosttable[idx3] && hosttable[idx3]->pool && idx3 != idx &&
              host_in_pool_p(hosttable[idx3], n))
            break;
        }
        if (idx3 < hosttable_size)
          continue; /* Host is also a member of another pool.  */
      }

      hi2 = hosttable[n];
      if (!hi2)
        ;
      else if (alive && hi2->dead) {
        hi2->dead = 0;
        err = ks_printf_help(ctrl, "marking '%s' as alive", hi2->name);
      } else if (!alive && !hi2->dead) {
        hi2->dead = 1;
        hi2->died_at = 0; /* Manually set dead. */
        err = ks_printf_help(ctrl, "marking '%s' as dead", hi2->name);
      }
    }
  }

  return err;
}

/* Debug function to print the entire hosttable.  */
gpg_error_t ks_hkp_print_hosttable(ctrl_t ctrl) {
  gpg_error_t err;
  int idx, idx2;
  hostinfo_t hi;
  membuf_t mb;
  time_t curtime;
  char *p, *died;
  const char *diedstr;

  err = ks_print_help(ctrl, "hosttable (idx, ipv6, ipv4, dead, name, time):");
  if (err) return err;

  /* FIXME: We need a lock for the hosttable.  */
  curtime = gnupg_get_time();
  for (idx = 0; idx < hosttable_size; idx++)
    if ((hi = hosttable[idx])) {
      if (hi->dead && hi->died_at) {
        died = elapsed_time_string(hi->died_at, curtime);
        diedstr = died ? died : "error";
      } else
        diedstr = died = NULL;

      if (!hi->iporname_valid) {
        char *canon = NULL;

        xfree(hi->iporname);
        hi->iporname = NULL;

        /* Do a lookup just for the display purpose.  */
        if (hi->onion || hi->pool)
          ;
        else if (is_ip_address(hi->name)) {
          dns_addrinfo_t aibuf, ai;

          /* Turn the numerical IP address string into an AI and
           * then do a DNS PTR lookup.  */
          if (!resolve_dns_name(hi->name, 0, 0, SOCK_STREAM, &aibuf, &canon)) {
            if (canon && is_ip_address(canon)) {
              xfree(canon);
              canon = NULL;
            }
            for (ai = aibuf; !canon && ai; ai = ai->next) {
              resolve_dns_addr(ai->addr, ai->addrlen, DNS_WITHBRACKET, &canon);
              if (canon && is_ip_address(canon)) {
                /* We already have the numeric IP - no need to
                 * display it a second time.  */
                xfree(canon);
                canon = NULL;
              }
            }
          }
          free_dns_addrinfo(aibuf);
        } else {
          dns_addrinfo_t aibuf, ai;

          /* Get the IP address as a string from a name.  Note
           * that resolve_dns_addr allocates CANON on success
           * and thus terminates the loop. */
          if (!resolve_dns_name(hi->name, 0, hi->v6 ? AF_INET6 : AF_INET,
                                SOCK_STREAM, &aibuf, NULL)) {
            for (ai = aibuf; !canon && ai; ai = ai->next) {
              resolve_dns_addr(ai->addr, ai->addrlen,
                               DNS_NUMERICHOST | DNS_WITHBRACKET, &canon);
            }
          }
          free_dns_addrinfo(aibuf);
        }

        hi->iporname = canon;
        hi->iporname_valid = 1;
      }

      err = ks_printf_help(
          ctrl, "%3d %s %s %s %s%s%s%s%s%s%s\n", idx,
          hi->onion ? "O" : hi->v6 ? "6" : " ", hi->v4 ? "4" : " ",
          hi->dead ? "d" : " ", hi->name, hi->iporname ? " (" : "",
          hi->iporname ? hi->iporname : "", hi->iporname ? ")" : "",
          diedstr ? "  (" : "", diedstr ? diedstr : "", diedstr ? ")" : "");
      xfree(died);
      if (err) return err;

      if (hi->cname) err = ks_printf_help(ctrl, "  .       %s", hi->cname);
      if (err) return err;

      if (hi->pool) {
        init_membuf(&mb, 256);
        put_membuf_printf(&mb, "  .   -->");
        for (idx2 = 0; idx2 < hi->pool_len && hi->pool[idx2] != -1; idx2++) {
          put_membuf_printf(&mb, " %d", hi->pool[idx2]);
          if (hi->poolidx == hi->pool[idx2]) put_membuf_printf(&mb, "*");
        }
        put_membuf(&mb, "", 1);
        p = (char *)get_membuf(&mb, NULL);
        if (!p) return gpg_error_from_syserror();
        err = ks_print_help(ctrl, p);
        xfree(p);
        if (err) return err;
      }
    }
  return 0;
}

/* Print a help output for the schemata supported by this module. */
gpg_error_t ks_hkp_help(ctrl_t ctrl, parsed_uri_t uri) {
  const char data[] =
      "Handler for HKP URLs:\n"
      "  hkp://\n"
      "  hkps://\n"
      "Supported methods: search, get, put\n";
  gpg_error_t err;

  const char data2[] = "  hkp\n  hkps";

  if (!uri)
    err = ks_print_help(ctrl, data2);
  else if (uri->is_http &&
           (!strcmp(uri->scheme, "hkp") || !strcmp(uri->scheme, "hkps")))
    err = ks_print_help(ctrl, data);
  else
    err = 0;

  return err;
}

/* Build the remote part of the URL from SCHEME, HOST and an optional
 * PORT.  Returns an allocated string at R_HOSTPORT or NULL on
 * failure.  If R_HTTPHOST is not NULL it receives a malloced string
 * with the hostname; this may be different from HOST if HOST is
 * selected from a pool.  */
static gpg_error_t make_host_part(ctrl_t ctrl, const char *scheme,
                                  const char *host, unsigned short port,
                                  int force_reselect, char **r_hostport,
                                  unsigned int *r_httpflags,
                                  char **r_httphost) {
  gpg_error_t err;
  char portstr[10];
  char *hostname;
  enum ks_protocol protocol;

  *r_hostport = NULL;

  if (!strcmp(scheme, "hkps") || !strcmp(scheme, "https")) {
    scheme = "https";
    protocol = KS_PROTOCOL_HKPS;
  } else /* HKP or HTTP.  */
  {
    scheme = "http";
    protocol = KS_PROTOCOL_HKP;
  }

  portstr[0] = 0;
  err = map_host(ctrl, host, force_reselect, protocol, &hostname, portstr,
                 r_httpflags, r_httphost);
  if (err) return err;

  /* If map_host did not return a port but a port has been specified
   * (implicitly or explicitly) then use that port.  In the case that
   * a port was not specified (which is probably a bug in https.c) we
   * will set up defaults.  */
  if (*portstr)
    ;
  else if (!*portstr && port)
    snprintf(portstr, sizeof portstr, "%hu", port);
  else if (!strcmp(scheme, "https"))
    strcpy(portstr, "443");
  else
    strcpy(portstr, "11371");

  if (*hostname != '[' && is_ip_address(hostname) == 6)
    *r_hostport = strconcat(scheme, "://[", hostname, "]:", portstr, NULL);
  else
    *r_hostport = strconcat(scheme, "://", hostname, ":", portstr, NULL);
  xfree(hostname);
  if (!*r_hostport) {
    if (r_httphost) {
      xfree(*r_httphost);
      *r_httphost = NULL;
    }
    return gpg_error_from_syserror();
  }
  return 0;
}

/* Resolve all known keyserver names and update the hosttable.  This
   is mainly useful for debugging because the resolving is anyway done
   on demand.  */
gpg_error_t ks_hkp_resolve(ctrl_t ctrl, parsed_uri_t uri) {
  gpg_error_t err;
  char *hostport = NULL;

  /* NB: With an explicitly given port we do not want to consult a
   * service record because that might be in conflict with the port
   * from such a service record.  */
  err = make_host_part(ctrl, uri->scheme, uri->host, uri->port, 1, &hostport,
                       NULL, NULL);
  if (err) {
    err = ks_printf_help(ctrl, "%s://%s:%hu: resolve failed: %s", uri->scheme,
                         uri->host, uri->port, gpg_strerror(err));
  } else {
    err = ks_printf_help(ctrl, "%s", hostport);
    xfree(hostport);
  }
  return err;
}

/* Housekeeping function called from the housekeeping thread.  It is
   used to mark dead hosts alive so that they may be tried again after
   some time.  */
void ks_hkp_housekeeping(time_t curtime) {
  int idx;
  hostinfo_t hi;

  for (idx = 0; idx < hosttable_size; idx++) {
    hi = hosttable[idx];
    if (!hi) continue;
    if (!hi->dead) continue;
    if (!hi->died_at) continue; /* Do not resurrect manually shot hosts.  */
    if (hi->died_at + RESURRECT_INTERVAL <= curtime || hi->died_at > curtime) {
      hi->dead = 0;
      log_info("resurrected host '%s'", hi->name);
    }
  }
}

/* Reload (SIGHUP) action for this module.  We mark all host alive
 * even those which have been manually shot.  */
void ks_hkp_reload(void) {
  int idx, count;
  hostinfo_t hi;

  for (idx = count = 0; idx < hosttable_size; idx++) {
    hi = hosttable[idx];
    if (!hi) continue;
    hi->iporname_valid = 0;
    if (!hi->dead) continue;
    hi->dead = 0;
    count++;
  }
  if (count) log_info("number of resurrected hosts: %d", count);
}

/* Send an HTTP request.  On success returns response in RESPONSE.
   HOSTPORTSTR is only used for diagnostics.  If HTTPHOST is not NULL
   it will be used as HTTP "Host" header.  If POST_CB is not NULL a
   post request is used and that callback is called to allow writing
   the post data.  If R_HTTP_STATUS is not NULL, the http status code
   will be stored there.  */
static gpg_error_t send_request(ctrl_t ctrl, const char *url,
                                const char *hostportstr, const char *httphost,
                                unsigned int httpflags,
                                boost::optional<std::string> post_data,
                                std::string &response,
                                unsigned int *r_http_status) {
  if (!url) return GPG_ERR_INV_ARG;

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

  NeoPG::Proto::Http request;

  /* We do it the other way around, leave URL normal and provide
     connect_to information in curl.  */
  NeoPG::Proto::URI uri(url);
  if (httphost) {
    std::string connect_to = uri.host;
    uri.host = httphost;
    request.set_connect_to(connect_to);
  }

  request.set_url(uri.str())
      .forbid_reuse()
      .set_timeout(ctrl->timeout)
      .no_cache();

  if (opt.http_proxy)
    request.set_proxy(opt.http_proxy);
  else
    request.default_proxy(opt.honor_http_proxy);

  if (opt.disable_ipv6)
    request.set_ipresolve(NeoPG::Proto::Http::Resolve::IPv4);
  else if (opt.disable_ipv4)
    request.set_ipresolve(NeoPG::Proto::Http::Resolve::IPv6);

  if (post_data) /* x-www-form-urlencoded is default */
    request.set_post(post_data);

  /* SSL Config.  It all boils down to a simple switch: Normally, we
     use the system CA list.  And for the SKS Poolserver, we take a
     baked in CA.  */
  if (!strcmp(httphost, "hkps.pool.sks-keyservers.net")) {
    char *pemname =
        make_filename_try(gnupg_datadir(), "sks-keyservers.netCA.pem", NULL);
    request.set_cainfo(pemname);
  }

  try {
    response = request.fetch();
  } catch (const std::runtime_error &e) {
    log_error(_("error retrieving '%s': %s\n"), url, e.what());
    return GPG_ERR_NO_DATA;
  }

  return 0;
}

/* Helper to evaluate the error code ERR from a send_request() call
   with REQUEST.  The function returns true if the caller shall try
   again.  TRIES_LEFT points to a variable to track the number of
   retries; this function decrements it and won't return true if it is
   down to zero. */
static int handle_send_request_error(ctrl_t ctrl, gpg_error_t err,
                                     const char *request,
                                     unsigned int *tries_left) {
  int retry = 0;

  /* Fixme: Should we disable all hosts of a protocol family if a
   * request for an address of that familiy returned ENETDOWN?  */

  switch (err) {
    case GPG_ERR_ECONNREFUSED:
    case GPG_ERR_ENETUNREACH:
    case GPG_ERR_ENETDOWN:
    case GPG_ERR_UNKNOWN_HOST:
    case GPG_ERR_NETWORK:
    case GPG_ERR_EIO: /* Sometimes used by estream cookie functions.  */
      if (mark_host_dead(request) && *tries_left) retry = 1;
      break;

    case GPG_ERR_ETIMEDOUT:
      if (*tries_left) {
        log_info("selecting a different host due to a timeout\n");
        retry = 1;
      }
      break;

    case GPG_ERR_EACCES:
      break;

    default:
      break;
  }

  if (*tries_left) --*tries_left;

  return retry;
}

/* Search the keyserver identified by URI for keys matching PATTERN.
   On success, data is in RESPONSE.  If R_HTTP_STATUS is not NULL, the
   http status code will be stored there.  */
gpg_error_t ks_hkp_search(ctrl_t ctrl, parsed_uri_t uri, const char *pattern,
                          std::string &response, unsigned int *r_http_status) {
  gpg_error_t err;
  KEYDB_SEARCH_DESC desc;
  char fprbuf[2 + 40 + 1];
  char *hostport = NULL;
  char *request = NULL;
  int reselect;
  unsigned int httpflags;
  char *httphost = NULL;
  unsigned int tries = SEND_REQUEST_RETRIES;

  /* Remove search type indicator and adjust PATTERN accordingly.
     Note that HKP keyservers like the 0x to be present when searching
     by keyid.  We need to re-format the fingerprint and keyids so to
     remove the gpg specific force-use-of-this-key flag ("!").  */
  err = classify_user_id(pattern, &desc, 1);
  if (err) return err;
  switch (desc.mode) {
    case KEYDB_SEARCH_MODE_EXACT:
    case KEYDB_SEARCH_MODE_SUBSTR:
    case KEYDB_SEARCH_MODE_MAIL:
    case KEYDB_SEARCH_MODE_MAILSUB:
      pattern = desc.u.name;
      break;
    case KEYDB_SEARCH_MODE_SHORT_KID:
      snprintf(fprbuf, sizeof fprbuf, "0x%08lX", (unsigned long)desc.u.kid[1]);
      pattern = fprbuf;
      break;
    case KEYDB_SEARCH_MODE_LONG_KID:
      snprintf(fprbuf, sizeof fprbuf, "0x%08lX%08lX",
               (unsigned long)desc.u.kid[0], (unsigned long)desc.u.kid[1]);
      pattern = fprbuf;
      break;
    case KEYDB_SEARCH_MODE_FPR16:
      fprbuf[0] = '0';
      fprbuf[1] = 'x';
      bin2hex(desc.u.fpr, 16, fprbuf + 2);
      pattern = fprbuf;
      break;
    case KEYDB_SEARCH_MODE_FPR20:
    case KEYDB_SEARCH_MODE_FPR:
      fprbuf[0] = '0';
      fprbuf[1] = 'x';
      bin2hex(desc.u.fpr, 20, fprbuf + 2);
      pattern = fprbuf;
      break;
    default:
      return GPG_ERR_INV_USER_ID;
  }

  /* Build the request string.  */
  reselect = 0;
again : {
  std::string searchkey;

  xfree(hostport);
  hostport = NULL;
  xfree(httphost);
  httphost = NULL;
  err = make_host_part(ctrl, uri->scheme, uri->host, uri->port, reselect,
                       &hostport, &httpflags, &httphost);
  if (err) goto leave;

  searchkey = http_escape_string(pattern, EXTRA_ESCAPE_CHARS);

  xfree(request);
  request = strconcat(hostport, "/pks/lookup?op=index&options=mr&search=",
                      searchkey.c_str(), NULL);
  if (!request) {
    err = gpg_error_from_syserror();
    goto leave;
  }
}

  /* Send the request.  */
  response.clear();
  err = send_request(ctrl, request, hostport, httphost, httpflags, boost::none,
                     response, r_http_status);
  if (handle_send_request_error(ctrl, err, request, &tries)) {
    reselect = 1;
    goto again;
  }
  if (err) goto leave;

  err = dirmngr_status(ctrl, "SOURCE", hostport, NULL);
  if (err) goto leave;

  /* Peek at the response.  */
  if (response.size() == 0)
    err = GPG_ERR_EOF;
  else if (response[0] == '<')
    /* The document begins with a '<': Assume a HTML response,
       which we don't support.  */
    err = GPG_ERR_UNSUPPORTED_ENCODING;

leave:
  xfree(request);
  xfree(hostport);
  xfree(httphost);
  return err;
}

/* Get the key described key the KEYSPEC string from the keyserver
   identified by URI.  On success data is in RESPONSE.  The data will
   be provided in a format GnuPG can import (either a binary OpenPGP
   message or an armored one).  */
gpg_error_t ks_hkp_get(ctrl_t ctrl, parsed_uri_t uri, const char *keyspec,
                       std::string &response) {
  gpg_error_t err;
  KEYDB_SEARCH_DESC desc;
  char kidbuf[2 + 40 + 1];
  const char *exactname = NULL;
  std::string searchkey;
  char *hostport = NULL;
  char *request = NULL;
  int reselect;
  char *httphost = NULL;
  unsigned int httpflags;
  unsigned int tries = SEND_REQUEST_RETRIES;

  /* Remove search type indicator and adjust PATTERN accordingly.
     Note that HKP keyservers like the 0x to be present when searching
     by keyid.  We need to re-format the fingerprint and keyids so to
     remove the gpg specific force-use-of-this-key flag ("!").  */
  err = classify_user_id(keyspec, &desc, 1);
  if (err) return err;
  switch (desc.mode) {
    case KEYDB_SEARCH_MODE_SHORT_KID:
      snprintf(kidbuf, sizeof kidbuf, "0x%08lX", (unsigned long)desc.u.kid[1]);
      break;
    case KEYDB_SEARCH_MODE_LONG_KID:
      snprintf(kidbuf, sizeof kidbuf, "0x%08lX%08lX",
               (unsigned long)desc.u.kid[0], (unsigned long)desc.u.kid[1]);
      break;
    case KEYDB_SEARCH_MODE_FPR20:
    case KEYDB_SEARCH_MODE_FPR:
      /* This is a v4 fingerprint. */
      kidbuf[0] = '0';
      kidbuf[1] = 'x';
      bin2hex(desc.u.fpr, 20, kidbuf + 2);
      break;

    case KEYDB_SEARCH_MODE_EXACT:
      exactname = desc.u.name;
      break;

    case KEYDB_SEARCH_MODE_FPR16:
      log_error("HKP keyservers do not support v3 fingerprints\n");
    /* fall through */
    default:
      return GPG_ERR_INV_USER_ID;
  }

  searchkey =
      http_escape_string(exactname ? exactname : kidbuf, EXTRA_ESCAPE_CHARS);

  reselect = 0;
again:
  /* Build the request string.  */
  xfree(hostport);
  hostport = NULL;
  xfree(httphost);
  httphost = NULL;
  err = make_host_part(ctrl, uri->scheme, uri->host, uri->port, reselect,
                       &hostport, &httpflags, &httphost);
  if (err) goto leave;

  xfree(request);
  request = strconcat(hostport, "/pks/lookup?op=get&options=mr&search=",
                      searchkey.c_str(), exactname ? "&exact=on" : "", NULL);
  if (!request) {
    err = gpg_error_from_syserror();
    goto leave;
  }

  /* Send the request.  */
  response.clear();
  err = send_request(ctrl, request, hostport, httphost, httpflags, boost::none,
                     response, NULL);
  if (handle_send_request_error(ctrl, err, request, &tries)) {
    reselect = 1;
    goto again;
  }
  if (err) goto leave;

  err = dirmngr_status(ctrl, "SOURCE", hostport, NULL);
  if (err) goto leave;

leave:
  xfree(request);
  xfree(hostport);
  xfree(httphost);
  return err;
}

/* Send the key in {DATA,DATALEN} to the keyserver identified by URI.  */
gpg_error_t ks_hkp_put(ctrl_t ctrl, parsed_uri_t uri, const void *data,
                       size_t datalen) {
  gpg_error_t err;
  char *hostport = NULL;
  char *request = NULL;
  char *armored = NULL;
  int reselect;
  char *httphost = NULL;
  unsigned int httpflags;
  unsigned int tries = SEND_REQUEST_RETRIES;
  std::string response;
  std::string post_data;

  err = armor_data(&armored, data, datalen);
  if (err) goto leave;

  post_data = "keytext=";
  post_data += http_escape_string(armored, EXTRA_ESCAPE_CHARS);

  xfree(armored);
  armored = NULL;

  /* Build the request string.  */
  reselect = 0;
again:
  xfree(hostport);
  hostport = NULL;
  xfree(httphost);
  httphost = NULL;
  err = make_host_part(ctrl, uri->scheme, uri->host, uri->port, reselect,
                       &hostport, &httpflags, &httphost);
  if (err) goto leave;

  xfree(request);
  request = strconcat(hostport, "/pks/add", NULL);
  if (!request) {
    err = gpg_error_from_syserror();
    goto leave;
  }

  /* Send the request.  */
  response.clear();
  err = send_request(ctrl, request, hostport, httphost, 0, post_data, response,
                     NULL);
  if (handle_send_request_error(ctrl, err, request, &tries)) {
    reselect = 1;
    goto again;
  }
  if (err) goto leave;

leave:
  xfree(armored);
  xfree(request);
  xfree(hostport);
  xfree(httphost);
  return err;
}
