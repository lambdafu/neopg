/* visibility.h - Set visibility attribute
 * Copyright (C) 2014  g10 Code GmbH
 *
 * This file is part of libgpg-error.
 *
 * libgpg-error is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * as published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * libgpg-error is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this program; if not, see <https://www.gnu.org/licenses/>.
 */

#ifndef _GPGRT_VISIBILITY_H
#define _GPGRT_VISIBILITY_H

/* Include the main header here so that public symbols are mapped to
   the internal underscored ones.  */
#ifdef _GPGRT_INCL_BY_VISIBILITY_C
#include "gpgrt-int.h"
#endif

/* Our use of the ELF visibility feature works by passing
   -fvisibiliy=hidden on the command line and by explicitly marking
   all exported functions as visible.

   NOTE: When adding new functions, please make sure to add them to
         gpg-error.vers and gpg-error.def.in as well.  */

#ifdef _GPGRT_INCL_BY_VISIBILITY_C

#else /*!_GPGRT_INCL_BY_VISIBILITY_C*/

/* To avoid accidental use of the public functions inside Libgpg-error,
   we redefine them to catch such errors.  */

#define gpg_strerror _gpgrt_USE_UNDERSCORED_FUNCTION
#define gpg_strerror_r _gpgrt_USE_UNDERSCORED_FUNCTION
#define gpg_err_set_errno _gpgrt_USE_UNDERSCORED_FUNCTION

#define gpgrt_fopen _gpgrt_USE_UNDERSCORED_FUNCTION
#define gpgrt_fopenmem _gpgrt_USE_UNDERSCORED_FUNCTION
#define gpgrt_fopenmem_init _gpgrt_USE_UNDERSCORED_FUNCTION
#define gpgrt_fdopen _gpgrt_USE_UNDERSCORED_FUNCTION
#define gpgrt_fdopen_nc _gpgrt_USE_UNDERSCORED_FUNCTION
#define gpgrt_fopencookie _gpgrt_USE_UNDERSCORED_FUNCTION
#define gpgrt_fclose _gpgrt_USE_UNDERSCORED_FUNCTION
#define gpgrt_fclose_snatch _gpgrt_USE_UNDERSCORED_FUNCTION
#define gpgrt_onclose _gpgrt_USE_UNDERSCORED_FUNCTION
#define gpgrt_fileno _gpgrt_USE_UNDERSCORED_FUNCTION
#define gpgrt_fileno_unlocked _gpgrt_USE_UNDERSCORED_FUNCTION
#define _gpgrt_get_std_stream _gpgrt_USE_UNDERSCORED_FUNCTION
#define gpgrt_flockfile _gpgrt_USE_UNDERSCORED_FUNCTION
#define gpgrt_funlockfile _gpgrt_USE_UNDERSCORED_FUNCTION
#define gpgrt_feof _gpgrt_USE_UNDERSCORED_FUNCTION
#define gpgrt_feof_unlocked _gpgrt_USE_UNDERSCORED_FUNCTION
#define gpgrt_ferror _gpgrt_USE_UNDERSCORED_FUNCTION
#define gpgrt_ferror_unlocked _gpgrt_USE_UNDERSCORED_FUNCTION
#define gpgrt_clearerr _gpgrt_USE_UNDERSCORED_FUNCTION
#define gpgrt_clearerr_unlocked _gpgrt_USE_UNDERSCORED_FUNCTION
#define gpgrt_fflush _gpgrt_USE_UNDERSCORED_FUNCTION
#define gpgrt_fseek _gpgrt_USE_UNDERSCORED_FUNCTION
#define gpgrt_fseeko _gpgrt_USE_UNDERSCORED_FUNCTION
#define gpgrt_ftell _gpgrt_USE_UNDERSCORED_FUNCTION
#define gpgrt_ftello _gpgrt_USE_UNDERSCORED_FUNCTION
#define gpgrt_rewind _gpgrt_USE_UNDERSCORED_FUNCTION
#define gpgrt_fgetc _gpgrt_USE_UNDERSCORED_FUNCTION
#define _gpgrt_getc_underflow _gpgrt_USE_DBLUNDERSCO_FUNCTION
#define gpgrt_fputc _gpgrt_USE_UNDERSCORED_FUNCTION
#define _gpgrt_putc_overflow _gpgrt_USE_DBLUNDERSCO_FUNCTION
#define gpgrt_ungetc _gpgrt_USE_UNDERSCORED_FUNCTION
#define gpgrt_read _gpgrt_USE_UNDERSCORED_FUNCTION
#define gpgrt_write _gpgrt_USE_UNDERSCORED_FUNCTION
#define gpgrt_write_sanitized _gpgrt_USE_UNDERSCORED_FUNCTION
#define gpgrt_fread _gpgrt_USE_UNDERSCORED_FUNCTION
#define gpgrt_fwrite _gpgrt_USE_UNDERSCORED_FUNCTION
#define gpgrt_fgets _gpgrt_USE_UNDERSCORED_FUNCTION
#define gpgrt_fputs _gpgrt_USE_UNDERSCORED_FUNCTION
#define gpgrt_fputs_unlocked _gpgrt_USE_UNDERSCORED_FUNCTION
#define gpgrt_read_line _gpgrt_USE_UNDERSCORED_FUNCTION
#define gpgrt_free _gpgrt_USE_UNDERSCORED_FUNCTION
#define gpgrt_fprintf _gpgrt_USE_UNDERSCORED_FUNCTION
#define gpgrt_fprintf_unlocked _gpgrt_USE_UNDERSCORED_FUNCTION
#define gpgrt_printf _gpgrt_USE_UNDERSCORED_FUNCTION
#define gpgrt_printf_unlocked _gpgrt_USE_UNDERSCORED_FUNCTION
#define gpgrt_vfprintf _gpgrt_USE_UNDERSCORED_FUNCTION
#define gpgrt_vfprintf_unlocked _gpgrt_USE_UNDERSCORED_FUNCTION
#define gpgrt_setvbuf _gpgrt_USE_UNDERSCORED_FUNCTION
#define gpgrt_setbuf _gpgrt_USE_UNDERSCORED_FUNCTION
#define gpgrt_set_binary _gpgrt_USE_UNDERSCORED_FUNCTION
#define gpgrt_asprintf _gpgrt_USE_UNDERSCORED_FUNCTION
#define gpgrt_vasprintf _gpgrt_USE_UNDERSCORED_FUNCTION
#define gpgrt_snprintf _gpgrt_USE_UNDERSCORED_FUNCTION

#define gpgrt_set_syscall_clamp _gpgrt_USE_UNDERSCORED_FUNCTION
#define gpgrt_get_syscall_clamp _gpgrt_USE_UNDERSCORED_FUNCTION
#define gpgrt_set_alloc_func _gpgrt_USE_UNDERSCORED_FUNCTION

#endif /*!_GPGRT_INCL_BY_VISIBILITY_C*/

#endif /*_GPGRT_VISIBILITY_H*/
