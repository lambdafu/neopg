/* visibility.h - Set visibility attribute
 * Copyright (C) 2007  Free Software Foundation, Inc.
 *
 * This file is part of Libgcrypt.
 *
 * Libgcrypt is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * Libgcrypt is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#ifndef GCRY_VISIBILITY_H
#define GCRY_VISIBILITY_H

/* Redefine all public symbols with an underscore unless we already
   use the underscore prefixed version internally.  */

/* Include the main header here so that public symbols are mapped to
   the internal underscored ones.  */
#ifdef _GCRY_INCLUDED_BY_VISIBILITY_C
#include "gcrypt-int.h"
/* None in this version.  */
#else
#include "gcrypt-int.h"
#endif

/* Prototypes of functions exported but not ready for use.  */
gpg_error_t gcry_md_get(gcry_md_hd_t hd, int algo, unsigned char *buffer,
                        int buflen);

/* A macro to flag a function as visible.  */
#ifdef GCRY_USE_VISIBILITY
#define MARK_VISIBLEX(name) \
  extern __typeof__(name) name __attribute__((visibility("default")));
#else
#define MARK_VISIBLEX(name) /* */
#endif

/* Now mark all symbols.  */

MARK_VISIBLEX(gcry_control)

MARK_VISIBLEX(gcry_set_log_handler)
MARK_VISIBLEX(gcry_set_outofcore_handler)
MARK_VISIBLEX(gcry_set_progress_handler)

MARK_VISIBLEX(gcry_malloc)
MARK_VISIBLEX(gcry_malloc_secure)
MARK_VISIBLEX(gcry_calloc)
MARK_VISIBLEX(gcry_calloc_secure)
MARK_VISIBLEX(gcry_realloc)
MARK_VISIBLEX(gcry_strdup)
MARK_VISIBLEX(gcry_is_secure)
MARK_VISIBLEX(gcry_xcalloc)
MARK_VISIBLEX(gcry_xcalloc_secure)
MARK_VISIBLEX(gcry_xmalloc)
MARK_VISIBLEX(gcry_xmalloc_secure)
MARK_VISIBLEX(gcry_xrealloc)
MARK_VISIBLEX(gcry_xstrdup)
MARK_VISIBLEX(gcry_free)

MARK_VISIBLEX(gcry_md_algo_info)
MARK_VISIBLEX(gcry_md_algo_name)
MARK_VISIBLEX(gcry_md_close)
MARK_VISIBLEX(gcry_md_copy)
MARK_VISIBLEX(gcry_md_ctl)
MARK_VISIBLEX(gcry_md_enable)
MARK_VISIBLEX(gcry_md_get)
MARK_VISIBLEX(gcry_md_get_algo)
MARK_VISIBLEX(gcry_md_get_algo_dlen)
MARK_VISIBLEX(gcry_md_hash_buffer)
MARK_VISIBLEX(gcry_md_hash_buffers)
MARK_VISIBLEX(gcry_md_info)
MARK_VISIBLEX(gcry_md_is_enabled)
MARK_VISIBLEX(gcry_md_is_secure)
MARK_VISIBLEX(gcry_md_map_name)
MARK_VISIBLEX(gcry_md_open)
MARK_VISIBLEX(gcry_md_read)
MARK_VISIBLEX(gcry_md_extract)
MARK_VISIBLEX(gcry_md_reset)
MARK_VISIBLEX(gcry_md_setkey)
MARK_VISIBLEX(gcry_md_write)
MARK_VISIBLEX(gcry_md_debug)

MARK_VISIBLEX(gcry_cipher_algo_info)
MARK_VISIBLEX(gcry_cipher_algo_name)
MARK_VISIBLEX(gcry_cipher_close)
MARK_VISIBLEX(gcry_cipher_setkey)
MARK_VISIBLEX(gcry_cipher_setiv)
MARK_VISIBLEX(gcry_cipher_setctr)
MARK_VISIBLEX(gcry_cipher_authenticate)
MARK_VISIBLEX(gcry_cipher_checktag)
MARK_VISIBLEX(gcry_cipher_gettag)
MARK_VISIBLEX(gcry_cipher_ctl)
MARK_VISIBLEX(gcry_cipher_decrypt)
MARK_VISIBLEX(gcry_cipher_encrypt)
MARK_VISIBLEX(gcry_cipher_get_algo_blklen)
MARK_VISIBLEX(gcry_cipher_get_algo_keylen)
MARK_VISIBLEX(gcry_cipher_info)
MARK_VISIBLEX(gcry_cipher_map_name)
MARK_VISIBLEX(gcry_cipher_mode_from_oid)
MARK_VISIBLEX(gcry_cipher_open)

MARK_VISIBLEX(gcry_mac_algo_info)
MARK_VISIBLEX(gcry_mac_algo_name)
MARK_VISIBLEX(gcry_mac_map_name)
MARK_VISIBLEX(gcry_mac_get_algo)
MARK_VISIBLEX(gcry_mac_get_algo_maclen)
MARK_VISIBLEX(gcry_mac_get_algo_keylen)
MARK_VISIBLEX(gcry_mac_open)
MARK_VISIBLEX(gcry_mac_close)
MARK_VISIBLEX(gcry_mac_setkey)
MARK_VISIBLEX(gcry_mac_setiv)
MARK_VISIBLEX(gcry_mac_write)
MARK_VISIBLEX(gcry_mac_read)
MARK_VISIBLEX(gcry_mac_verify)
MARK_VISIBLEX(gcry_mac_ctl)

MARK_VISIBLEX(gcry_pk_algo_info)
MARK_VISIBLEX(gcry_pk_algo_name)
MARK_VISIBLEX(gcry_pk_ctl)
MARK_VISIBLEX(gcry_pk_decrypt)
MARK_VISIBLEX(gcry_pk_encrypt)
MARK_VISIBLEX(gcry_pk_genkey)
MARK_VISIBLEX(gcry_pk_get_keygrip)
MARK_VISIBLEX(gcry_pk_get_curve)
MARK_VISIBLEX(gcry_pk_get_param)
MARK_VISIBLEX(gcry_pk_get_nbits)
MARK_VISIBLEX(gcry_pk_map_name)
MARK_VISIBLEX(gcry_pk_sign)
MARK_VISIBLEX(gcry_pk_testkey)
MARK_VISIBLEX(gcry_pk_verify)
MARK_VISIBLEX(gcry_pubkey_get_sexp)

MARK_VISIBLEX(gcry_random_add_bytes)
MARK_VISIBLEX(gcry_random_bytes)
MARK_VISIBLEX(gcry_random_bytes_secure)
MARK_VISIBLEX(gcry_randomize)
MARK_VISIBLEX(gcry_create_nonce)

MARK_VISIBLEX(gcry_sexp_alist)
MARK_VISIBLEX(gcry_sexp_append)
MARK_VISIBLEX(gcry_sexp_build)
MARK_VISIBLEX(gcry_sexp_build_array)
MARK_VISIBLEX(gcry_sexp_cadr)
MARK_VISIBLEX(gcry_sexp_canon_len)
MARK_VISIBLEX(gcry_sexp_car)
MARK_VISIBLEX(gcry_sexp_cdr)
MARK_VISIBLEX(gcry_sexp_cons)
MARK_VISIBLEX(gcry_sexp_create)
MARK_VISIBLEX(gcry_sexp_dump)
MARK_VISIBLEX(gcry_sexp_find_token)
MARK_VISIBLEX(gcry_sexp_length)
MARK_VISIBLEX(gcry_sexp_new)
MARK_VISIBLEX(gcry_sexp_nth)
MARK_VISIBLEX(gcry_sexp_nth_buffer)
MARK_VISIBLEX(gcry_sexp_nth_data)
MARK_VISIBLEX(gcry_sexp_nth_mpi)
MARK_VISIBLEX(gcry_sexp_nth_string)
MARK_VISIBLEX(gcry_sexp_prepend)
MARK_VISIBLEX(gcry_sexp_release)
MARK_VISIBLEX(gcry_sexp_sprint)
MARK_VISIBLEX(gcry_sexp_sscan)
MARK_VISIBLEX(gcry_sexp_vlist)
MARK_VISIBLEX(gcry_sexp_extract_param)

MARK_VISIBLEX(gcry_mpi_abs)
MARK_VISIBLEX(gcry_mpi_add)
MARK_VISIBLEX(gcry_mpi_add_ui)
MARK_VISIBLEX(gcry_mpi_addm)
MARK_VISIBLEX(gcry_mpi_aprint)
MARK_VISIBLEX(gcry_mpi_clear_bit)
MARK_VISIBLEX(gcry_mpi_clear_flag)
MARK_VISIBLEX(gcry_mpi_clear_highbit)
MARK_VISIBLEX(gcry_mpi_cmp)
MARK_VISIBLEX(gcry_mpi_cmp_ui)
MARK_VISIBLEX(gcry_mpi_copy)
MARK_VISIBLEX(gcry_mpi_div)
MARK_VISIBLEX(gcry_mpi_dump)
MARK_VISIBLEX(gcry_mpi_ec_add)
MARK_VISIBLEX(gcry_mpi_ec_sub)
MARK_VISIBLEX(gcry_mpi_ec_curve_point)
MARK_VISIBLEX(gcry_mpi_ec_dup)
MARK_VISIBLEX(gcry_mpi_ec_decode_point)
MARK_VISIBLEX(gcry_mpi_ec_get_affine)
MARK_VISIBLEX(gcry_mpi_ec_mul)
MARK_VISIBLEX(gcry_mpi_ec_new)
MARK_VISIBLEX(gcry_mpi_ec_get_mpi)
MARK_VISIBLEX(gcry_mpi_ec_get_point)
MARK_VISIBLEX(gcry_mpi_ec_set_mpi)
MARK_VISIBLEX(gcry_mpi_ec_set_point)
MARK_VISIBLEX(gcry_mpi_gcd)
MARK_VISIBLEX(gcry_mpi_get_flag)
MARK_VISIBLEX(gcry_mpi_get_nbits)
MARK_VISIBLEX(gcry_mpi_get_opaque)
MARK_VISIBLEX(gcry_mpi_is_neg)
MARK_VISIBLEX(gcry_mpi_invm)
MARK_VISIBLEX(gcry_mpi_mod)
MARK_VISIBLEX(gcry_mpi_mul)
MARK_VISIBLEX(gcry_mpi_mul_2exp)
MARK_VISIBLEX(gcry_mpi_mul_ui)
MARK_VISIBLEX(gcry_mpi_mulm)
MARK_VISIBLEX(gcry_mpi_neg)
MARK_VISIBLEX(gcry_mpi_new)
MARK_VISIBLEX(gcry_mpi_point_get)
MARK_VISIBLEX(gcry_mpi_point_new)
MARK_VISIBLEX(gcry_mpi_point_release)
MARK_VISIBLEX(gcry_mpi_point_set)
MARK_VISIBLEX(gcry_mpi_point_snatch_get)
MARK_VISIBLEX(gcry_mpi_point_snatch_set)
MARK_VISIBLEX(gcry_mpi_powm)
MARK_VISIBLEX(gcry_mpi_print)
MARK_VISIBLEX(gcry_mpi_randomize)
MARK_VISIBLEX(gcry_mpi_release)
MARK_VISIBLEX(gcry_mpi_rshift)
MARK_VISIBLEX(gcry_mpi_lshift)
MARK_VISIBLEX(gcry_mpi_scan)
MARK_VISIBLEX(gcry_mpi_snatch)
MARK_VISIBLEX(gcry_mpi_set)
MARK_VISIBLEX(gcry_mpi_set_bit)
MARK_VISIBLEX(gcry_mpi_set_flag)
MARK_VISIBLEX(gcry_mpi_set_highbit)
MARK_VISIBLEX(gcry_mpi_set_opaque)
MARK_VISIBLEX(gcry_mpi_set_opaque_copy)
MARK_VISIBLEX(gcry_mpi_set_ui)
MARK_VISIBLEX(gcry_mpi_snew)
MARK_VISIBLEX(gcry_mpi_sub)
MARK_VISIBLEX(gcry_mpi_sub_ui)
MARK_VISIBLEX(gcry_mpi_subm)
MARK_VISIBLEX(gcry_mpi_swap)
MARK_VISIBLEX(gcry_mpi_test_bit)

MARK_VISIBLEX(gcry_ctx_release)

MARK_VISIBLEX(gcry_log_debug)
MARK_VISIBLEX(gcry_log_debughex)
MARK_VISIBLEX(gcry_log_debugmpi)
MARK_VISIBLEX(gcry_log_debugpnt)
MARK_VISIBLEX(gcry_log_debugsxp)

/* Functions used to implement macros.  */
MARK_VISIBLEX(_gcry_mpi_get_const)

#undef MARK_VISIBLEX

#endif /*GCRY_VISIBILITY_H*/
