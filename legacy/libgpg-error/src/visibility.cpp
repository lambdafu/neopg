/* visibility.c - Wrapper for all public functions.
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

#include <config.h>
#include <stdarg.h>

#define _GPGRT_INCL_BY_VISIBILITY_C 1
#include "gpgrt-int.h"

const char *gpg_strerror(gpg_error_t err) { return _gpg_strerror(err); }

void gpg_err_set_errno(int err) { _gpg_err_set_errno(err); }

void gpgrt_set_syscall_clamp(void (*pre)(void), void (*post)(void)) {
  _gpgrt_set_syscall_clamp(pre, post);
}

void gpgrt_get_syscall_clamp(void (**r_pre)(void), void (**r_post)(void)) {
  _gpgrt_get_syscall_clamp(r_pre, r_post);
}

void gpgrt_set_alloc_func(void *(*f)(void *a, size_t n)) {
  _gpgrt_set_alloc_func(f);
}

estream_t gpgrt_fopen(const char *_GPGRT__RESTRICT path,
                      const char *_GPGRT__RESTRICT mode) {
  return _gpgrt_fopen(path, mode);
}

estream_t gpgrt_fopenmem(size_t memlimit, const char *_GPGRT__RESTRICT mode) {
  return _gpgrt_fopenmem(memlimit, mode);
}

estream_t gpgrt_fopenmem_init(size_t memlimit,
                              const char *_GPGRT__RESTRICT mode,
                              const void *data, size_t datalen) {
  return _gpgrt_fopenmem_init(memlimit, mode, data, datalen);
}

estream_t gpgrt_fdopen(int filedes, const char *mode) {
  return _gpgrt_fdopen(filedes, mode);
}

estream_t gpgrt_fdopen_nc(int filedes, const char *mode) {
  return _gpgrt_fdopen_nc(filedes, mode);
}

estream_t gpgrt_fopencookie(void *_GPGRT__RESTRICT cookie,
                            const char *_GPGRT__RESTRICT mode,
                            gpgrt_cookie_io_functions_t functions) {
  return _gpgrt_fopencookie(cookie, mode, functions);
}

int gpgrt_fclose(estream_t stream) { return _gpgrt_fclose(stream); }

int gpgrt_fclose_snatch(estream_t stream, void **r_buffer, size_t *r_buflen) {
  return _gpgrt_fclose_snatch(stream, r_buffer, r_buflen);
}

int gpgrt_onclose(estream_t stream, int mode, void (*fnc)(estream_t, void *),
                  void *fnc_value) {
  return _gpgrt_onclose(stream, mode, fnc, fnc_value);
}

int gpgrt_fileno(estream_t stream) { return _gpgrt_fileno(stream); }

int gpgrt_fileno_unlocked(estream_t stream) {
  return _gpgrt_fileno_unlocked(stream);
}

estream_t _gpgrt_get_std_stream(int fd) {
  return _gpgrt__get_std_stream(fd); /* (double dash in name) */
}

void gpgrt_flockfile(estream_t stream) { _gpgrt_flockfile(stream); }

void gpgrt_funlockfile(estream_t stream) { _gpgrt_funlockfile(stream); }

int gpgrt_feof(estream_t stream) { return _gpgrt_feof(stream); }

int gpgrt_feof_unlocked(estream_t stream) {
  return _gpgrt_feof_unlocked(stream);
}

int gpgrt_ferror(estream_t stream) { return _gpgrt_ferror(stream); }

int gpgrt_ferror_unlocked(estream_t stream) {
  return _gpgrt_ferror_unlocked(stream);
}

void gpgrt_clearerr(estream_t stream) { _gpgrt_clearerr(stream); }

void gpgrt_clearerr_unlocked(estream_t stream) {
  _gpgrt_clearerr_unlocked(stream);
}

int gpgrt_fflush(estream_t stream) { return _gpgrt_fflush(stream); }

int gpgrt_fseek(estream_t stream, long int offset, int whence) {
  return _gpgrt_fseek(stream, offset, whence);
}

int gpgrt_fseeko(estream_t stream, gpgrt_off_t offset, int whence) {
  return _gpgrt_fseeko(stream, offset, whence);
}

long int gpgrt_ftell(estream_t stream) { return _gpgrt_ftell(stream); }

gpgrt_off_t gpgrt_ftello(estream_t stream) { return _gpgrt_ftello(stream); }

void gpgrt_rewind(estream_t stream) { _gpgrt_rewind(stream); }

int gpgrt_fgetc(estream_t stream) { return _gpgrt_fgetc(stream); }

int _gpgrt_getc_underflow(estream_t stream) {
  return _gpgrt__getc_underflow(stream);
}

int gpgrt_fputc(int c, estream_t stream) { return _gpgrt_fputc(c, stream); }

int _gpgrt_putc_overflow(int c, estream_t stream) {
  return _gpgrt__putc_overflow(c, stream);
}

int gpgrt_ungetc(int c, estream_t stream) { return _gpgrt_ungetc(c, stream); }

int gpgrt_read(estream_t _GPGRT__RESTRICT stream, void *_GPGRT__RESTRICT buffer,
               size_t bytes_to_read, size_t *_GPGRT__RESTRICT bytes_read) {
  return _gpgrt_read(stream, buffer, bytes_to_read, bytes_read);
}

int gpgrt_write(estream_t _GPGRT__RESTRICT stream,
                const void *_GPGRT__RESTRICT buffer, size_t bytes_to_write,
                size_t *_GPGRT__RESTRICT bytes_written) {
  return _gpgrt_write(stream, buffer, bytes_to_write, bytes_written);
}

int gpgrt_write_sanitized(estream_t _GPGRT__RESTRICT stream,
                          const void *_GPGRT__RESTRICT buffer, size_t length,
                          const char *delimiters,
                          size_t *_GPGRT__RESTRICT bytes_written) {
  return _gpgrt_write_sanitized(stream, buffer, length, delimiters,
                                bytes_written);
}

size_t gpgrt_fread(void *_GPGRT__RESTRICT ptr, size_t size, size_t nitems,
                   estream_t _GPGRT__RESTRICT stream) {
  return _gpgrt_fread(ptr, size, nitems, stream);
}

size_t gpgrt_fwrite(const void *_GPGRT__RESTRICT ptr, size_t size,
                    size_t nitems, estream_t _GPGRT__RESTRICT stream) {
  return _gpgrt_fwrite(ptr, size, nitems, stream);
}

char *gpgrt_fgets(char *_GPGRT__RESTRICT buffer, int length,
                  estream_t _GPGRT__RESTRICT stream) {
  return _gpgrt_fgets(buffer, length, stream);
}

int gpgrt_fputs(const char *_GPGRT__RESTRICT s,
                estream_t _GPGRT__RESTRICT stream) {
  return _gpgrt_fputs(s, stream);
}

int gpgrt_fputs_unlocked(const char *_GPGRT__RESTRICT s,
                         estream_t _GPGRT__RESTRICT stream) {
  return _gpgrt_fputs_unlocked(s, stream);
}

gpgrt_ssize_t gpgrt_read_line(estream_t stream, char **addr_of_buffer,
                              size_t *length_of_buffer, size_t *max_length) {
  return _gpgrt_read_line(stream, addr_of_buffer, length_of_buffer, max_length);
}

void gpgrt_free(void *a) {
  if (a) _gpgrt_free(a);
}

int gpgrt_vfprintf(estream_t _GPGRT__RESTRICT stream,
                   const char *_GPGRT__RESTRICT format, va_list ap) {
  return _gpgrt_vfprintf(stream, format, ap);
}

int gpgrt_vfprintf_unlocked(estream_t _GPGRT__RESTRICT stream,
                            const char *_GPGRT__RESTRICT format, va_list ap) {
  return _gpgrt_vfprintf_unlocked(stream, format, ap);
}

int gpgrt_printf(const char *_GPGRT__RESTRICT format, ...) {
  va_list ap;
  int rc;

  va_start(ap, format);
  rc = _gpgrt_vfprintf(es_stdout, format, ap);
  va_end(ap);

  return rc;
}

int gpgrt_printf_unlocked(const char *_GPGRT__RESTRICT format, ...) {
  va_list ap;
  int rc;

  va_start(ap, format);
  rc = _gpgrt_vfprintf_unlocked(es_stdout, format, ap);
  va_end(ap);

  return rc;
}

int gpgrt_fprintf(estream_t _GPGRT__RESTRICT stream,
                  const char *_GPGRT__RESTRICT format, ...) {
  va_list ap;
  int rc;

  va_start(ap, format);
  rc = _gpgrt_vfprintf(stream, format, ap);
  va_end(ap);

  return rc;
}

int gpgrt_fprintf_unlocked(estream_t _GPGRT__RESTRICT stream,
                           const char *_GPGRT__RESTRICT format, ...) {
  va_list ap;
  int rc;

  va_start(ap, format);
  rc = _gpgrt_vfprintf_unlocked(stream, format, ap);
  va_end(ap);

  return rc;
}

int gpgrt_setvbuf(estream_t _GPGRT__RESTRICT stream, char *_GPGRT__RESTRICT buf,
                  int type, size_t size) {
  return _gpgrt_setvbuf(stream, buf, type, size);
}

void gpgrt_setbuf(estream_t _GPGRT__RESTRICT stream,
                  char *_GPGRT__RESTRICT buf) {
  _gpgrt_setvbuf(stream, buf, buf ? _IOFBF : _IONBF, BUFSIZ);
}

void gpgrt_set_binary(estream_t stream) { _gpgrt_set_binary(stream); }

int gpgrt_asprintf(char **r_buf, const char *_GPGRT__RESTRICT format, ...) {
  va_list ap;
  int rc;

  va_start(ap, format);
  rc = _gpgrt_estream_vasprintf(r_buf, format, ap);
  va_end(ap);

  return rc;
}

int gpgrt_vasprintf(char **r_buf, const char *_GPGRT__RESTRICT format,
                    va_list ap) {
  return _gpgrt_estream_vasprintf(r_buf, format, ap);
}

int gpgrt_snprintf(char *buf, size_t bufsize, const char *format, ...) {
  int rc;
  va_list arg_ptr;

  va_start(arg_ptr, format);
  rc = _gpgrt_estream_vsnprintf(buf, bufsize, format, arg_ptr);
  va_end(arg_ptr);

  return rc;
}

#include <string.h>

/* Code taken from glibc-2.2.1/sysdeps/generic/strsep.c. */
char *gpg_strsep(char **stringp, const char *delim) {
  char *begin, *end;

  begin = *stringp;
  if (begin == NULL) return NULL;

  /* A frequent case is when the delimiter string contains only one
     character.  Here we don't need to call the expensive 'strpbrk'
     function and instead work using 'strchr'.  */
  if (delim[0] == '\0' || delim[1] == '\0') {
    char ch = delim[0];

    if (ch == '\0')
      end = NULL;
    else {
      if (*begin == ch)
        end = begin;
      else if (*begin == '\0')
        end = NULL;
      else
        end = strchr(begin + 1, ch);
    }
  } else
    /* Find the end of the token.  */
    end = strpbrk(begin, delim);

  if (end) {
    /* Terminate the token and set *STRINGP past NUL character.  */
    *end++ = '\0';
    *stringp = end;
  } else
    /* No more delimiters; this is the last token.  */
    *stringp = NULL;

  return begin;
}
