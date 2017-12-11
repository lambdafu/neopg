/* dns-stuff.c - DNS related code including CERT RR (rfc-4398)
 * Copyright (C) 2006 Free Software Foundation, Inc.
 * Copyright (C) 2006, 2015 Werner Koch
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
#ifndef GNUPG_DIRMNGR_DNS_STUFF_H
#define GNUPG_DIRMNGR_DNS_STUFF_H

#ifdef HAVE_W32_SYSTEM
#ifdef HAVE_WINSOCK2_H
#include <winsock2.h>
#endif
#include <windows.h>
#else
#include <sys/socket.h>
#include <sys/types.h>
#endif

/*
 * Flags used with resolve_dns_addr.
 */
#define DNS_NUMERICHOST 1 /* Force numeric output format.  */
#define DNS_WITHBRACKET               \
  2 /* Put brackets around numeric v6 \
       addresses.  */

struct dns_addrinfo_s;
typedef struct dns_addrinfo_s *dns_addrinfo_t;
struct dns_addrinfo_s {
  dns_addrinfo_t next;
  int family;
  int socktype;
  int protocol;
  int addrlen;
  struct sockaddr_storage addr[1];
};

/* Set verbosity and debug mode for this module. */
void set_dns_verbose(int verbose, int debug);

/* Set the Disable-IPv4 flag so that the name resolver does not return
 * A addresses.  */
void set_dns_disable_ipv4(int yes);

/* Set the Disable-IPv6 flag so that the name resolver does not return
 * AAAA addresses.  */
void set_dns_disable_ipv6(int yes);

/* Set the timeout for libdns requests to SECONDS.  */
void set_dns_timeout(int seconds);

/* Calling this function with YES set to True forces the use of the
 * standard resolver even if dirmngr has been built with support for
 * an alternative resolver.  */
void enable_standard_resolver(int yes);

/* Return true if the standard resolver is used.  */
int standard_resolver_p(void);

/* Calling this function with YES switches libdns into recursive mode.
 * It has no effect on the standard resolver.  */
void enable_recursive_resolver(int yes);

/* Return true iff the recursive resolver is used.  */
int recursive_resolver_p(void);

/* SIGHUP action handler for this module.  */
void reload_dns_stuff(int force);

void free_dns_addrinfo(dns_addrinfo_t ai);

/* Function similar to getaddrinfo.  */
gpg_error_t resolve_dns_name(const char *name, unsigned short port,
                             int want_family, int want_socktype,
                             dns_addrinfo_t *r_dai, char **r_canonname);

/* Function similar to getnameinfo.  */
gpg_error_t resolve_dns_addr(const struct sockaddr_storage *addr, int addrlen,
                             unsigned int flags, char **r_name);

/* Return true if NAME is a numerical IP address.  */
int is_ip_address(const char *name);

/* Return true if NAME is an onion address.  */
int is_onion_address(const char *name);

/* Get the canonical name for NAME.  */
gpg_error_t get_dns_cname(const char *name, char **r_cname);

#endif /*GNUPG_DIRMNGR_DNS_STUFF_H*/
