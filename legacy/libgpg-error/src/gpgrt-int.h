/* gpgrt-int.h - Internal definitions
 * Copyright (C) 2014 g10 Code GmbH
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

#ifndef _GPGRT_GPGRT_INT_H
#define _GPGRT_GPGRT_INT_H

#include <mutex>

#include "gpg-error.h"
#include "visibility.h"

/* Local error function prototypes.  */
const char *_gpg_strerror(gpg_error_t err);
void _gpg_err_set_errno(int err);

void _gpgrt_set_alloc_func(void *(*f)(void *a, size_t n));

void *_gpgrt_realloc(void *a, size_t n);
void *_gpgrt_malloc(size_t n);
void _gpgrt_free(void *a);

/* Local definitions for estream.  */

#if _WIN32
#ifndef O_NONBLOCK
#define O_NONBLOCK 0x40000000 /* FIXME: Is that safe?  */
#endif
#endif

/*
 * A private cookie function to implement an internal IOCTL service.
 * and ist IOCTL numbers.
 */
typedef int (*cookie_ioctl_function_t)(void *cookie, int cmd, void *ptr,
                                       size_t *len);
#define COOKIE_IOCTL_SNATCH_BUFFER 1
#define COOKIE_IOCTL_NONBLOCK 2

/* An internal variant of gpgrt_cookie_close_function_t with a slot
   for the ioctl function.  */
struct cookie_io_functions_s {
  struct _gpgrt_cookie_io_functions public_x;
  cookie_ioctl_function_t func_ioctl;
};

typedef enum {
  BACKEND_MEM,
  BACKEND_FD,
  BACKEND_W32,
  BACKEND_FP,
  BACKEND_USER,
  BACKEND_W32_POLLABLE
} gpgrt_stream_backend_kind_t;

/*
 * A type to hold notification functions.
 */
struct notify_list_s {
  struct notify_list_s *next;
  void (*fnc)(estream_t, void *); /* The notification function.  */
  void *fnc_value;                /* The value to be passed to FNC.  */
};
typedef struct notify_list_s *notify_list_t;

/*
 * Buffer management layer.
 */

#define BUFFER_BLOCK_SIZE BUFSIZ
#define BUFFER_UNREAD_SIZE 16

/*
 * The private object describing a stream.
 */
struct _gpgrt_stream_internal {
  unsigned char buffer[BUFFER_BLOCK_SIZE];
  unsigned char unread_buffer[BUFFER_UNREAD_SIZE];

  std::mutex *lock; /* Lock.  Used by *_stream_lock(). */

  gpgrt_stream_backend_kind_t kind;
  void *cookie;           /* Cookie.                */
  void *opaque;           /* Opaque data.           */
  unsigned int modeflags; /* Flags for the backend. */
  char *printable_fname;  /* Malloced filename for es_fname_get.  */
  gpgrt_off_t offset;
  gpgrt_cookie_read_function_t func_read;
  gpgrt_cookie_write_function_t func_write;
  gpgrt_cookie_seek_function_t func_seek;
  gpgrt_cookie_close_function_t func_close;
  cookie_ioctl_function_t func_ioctl;
  int strategy;
  es_syshd_t syshd; /* A copy of the system handle.  */
  struct {
    unsigned int err : 1;
    unsigned int eof : 1;
    unsigned int hup : 1;
  } indicators;
  unsigned int deallocate_buffer : 1;
  unsigned int is_stdstream : 1; /* This is a standard stream.  */
  unsigned int stdstream_fd : 2; /* 0, 1 or 2 for a standard stream.  */
  size_t print_ntotal;           /* Bytes written from in print_writer. */
  notify_list_t onclose;         /* On close notify function list.  */
};
typedef struct _gpgrt_stream_internal *estream_internal_t;

/* Local prototypes for estream.  */
int _gpgrt_estream_init(void);

gpgrt_stream_t _gpgrt_fopen(const char *_GPGRT__RESTRICT path,
                            const char *_GPGRT__RESTRICT mode);
gpgrt_stream_t _gpgrt_fopenmem(size_t memlimit,
                               const char *_GPGRT__RESTRICT mode);
gpgrt_stream_t _gpgrt_fopenmem_init(size_t memlimit,
                                    const char *_GPGRT__RESTRICT mode,
                                    const void *data, size_t datalen);
gpgrt_stream_t _gpgrt_fdopen(int filedes, const char *mode);
gpgrt_stream_t _gpgrt_fdopen_nc(int filedes, const char *mode);
gpgrt_stream_t _gpgrt_fopencookie(void *_GPGRT__RESTRICT cookie,
                                  const char *_GPGRT__RESTRICT mode,
                                  gpgrt_cookie_io_functions_t functions);
int _gpgrt_fclose(gpgrt_stream_t stream);
int _gpgrt_fclose_snatch(gpgrt_stream_t stream, void **r_buffer,
                         size_t *r_buflen);
int _gpgrt_onclose(gpgrt_stream_t stream, int mode,
                   void (*fnc)(gpgrt_stream_t, void *), void *fnc_value);
int _gpgrt_fileno(gpgrt_stream_t stream);
int _gpgrt_fileno_unlocked(gpgrt_stream_t stream);

gpgrt_stream_t _gpgrt__get_std_stream(int fd);

void _gpgrt_flockfile(gpgrt_stream_t stream);
void _gpgrt_funlockfile(gpgrt_stream_t stream);

int _gpgrt_feof(gpgrt_stream_t stream);
int _gpgrt_feof_unlocked(gpgrt_stream_t stream);
int _gpgrt_ferror(gpgrt_stream_t stream);
int _gpgrt_ferror_unlocked(gpgrt_stream_t stream);
void _gpgrt_clearerr(gpgrt_stream_t stream);
void _gpgrt_clearerr_unlocked(gpgrt_stream_t stream);

int _gpgrt_fflush(gpgrt_stream_t stream);
int _gpgrt_fseek(gpgrt_stream_t stream, long int offset, int whence);
int _gpgrt_fseeko(gpgrt_stream_t stream, gpgrt_off_t offset, int whence);
long int _gpgrt_ftell(gpgrt_stream_t stream);
gpgrt_off_t _gpgrt_ftello(gpgrt_stream_t stream);
void _gpgrt_rewind(gpgrt_stream_t stream);

int _gpgrt_fgetc(gpgrt_stream_t stream);
int _gpgrt_fputc(int c, gpgrt_stream_t stream);

int _gpgrt__getc_underflow(gpgrt_stream_t stream);
int _gpgrt__putc_overflow(int c, gpgrt_stream_t stream);

/* Note: Keeps the next two macros in sync
         with their counterparts in gpg-error.h. */
#define _gpgrt_getc_unlocked(stream)                        \
  (((!(stream)->flags.writing) &&                           \
    ((stream)->data_offset < (stream)->data_len) &&         \
    (!(stream)->unread_data_len))                           \
       ? ((int)(stream)->buffer[((stream)->data_offset)++]) \
       : _gpgrt__getc_underflow((stream)))

#define _gpgrt_putc_unlocked(c, stream)                             \
  (((stream)->flags.writing &&                                      \
    ((stream)->data_offset < (stream)->buffer_size) && (c != '\n')) \
       ? ((int)((stream)->buffer[((stream)->data_offset)++] = (c))) \
       : _gpgrt__putc_overflow((c), (stream)))

int _gpgrt_ungetc(int c, gpgrt_stream_t stream);

int _gpgrt_read(gpgrt_stream_t _GPGRT__RESTRICT stream,
                void *_GPGRT__RESTRICT buffer, size_t bytes_to_read,
                size_t *_GPGRT__RESTRICT bytes_read);
int _gpgrt_write(gpgrt_stream_t _GPGRT__RESTRICT stream,
                 const void *_GPGRT__RESTRICT buffer, size_t bytes_to_write,
                 size_t *_GPGRT__RESTRICT bytes_written);
int _gpgrt_write_sanitized(gpgrt_stream_t _GPGRT__RESTRICT stream,
                           const void *_GPGRT__RESTRICT buffer, size_t length,
                           const char *delimiters,
                           size_t *_GPGRT__RESTRICT bytes_written);

size_t _gpgrt_fread(void *_GPGRT__RESTRICT ptr, size_t size, size_t nitems,
                    gpgrt_stream_t _GPGRT__RESTRICT stream);
size_t _gpgrt_fwrite(const void *_GPGRT__RESTRICT ptr, size_t size, size_t memb,
                     gpgrt_stream_t _GPGRT__RESTRICT stream);

char *_gpgrt_fgets(char *_GPGRT__RESTRICT s, int n,
                   gpgrt_stream_t _GPGRT__RESTRICT stream);
int _gpgrt_fputs(const char *_GPGRT__RESTRICT s,
                 gpgrt_stream_t _GPGRT__RESTRICT stream);
int _gpgrt_fputs_unlocked(const char *_GPGRT__RESTRICT s,
                          gpgrt_stream_t _GPGRT__RESTRICT stream);

gpgrt_ssize_t _gpgrt_read_line(gpgrt_stream_t stream, char **addr_of_buffer,
                               size_t *length_of_buffer, size_t *max_length);

int _gpgrt_fprintf(gpgrt_stream_t _GPGRT__RESTRICT stream,
                   const char *_GPGRT__RESTRICT format, ...)
    GPGRT_ATTR_PRINTF(2, 3);
int _gpgrt_fprintf_unlocked(gpgrt_stream_t _GPGRT__RESTRICT stream,
                            const char *_GPGRT__RESTRICT format, ...)
    GPGRT_ATTR_PRINTF(2, 3);

int _gpgrt_vfprintf(gpgrt_stream_t _GPGRT__RESTRICT stream,
                    const char *_GPGRT__RESTRICT format, va_list ap)
    GPGRT_ATTR_PRINTF(2, 0);
int _gpgrt_vfprintf_unlocked(gpgrt_stream_t _GPGRT__RESTRICT stream,
                             const char *_GPGRT__RESTRICT format, va_list ap)
    GPGRT_ATTR_PRINTF(2, 0);

int _gpgrt_setvbuf(gpgrt_stream_t _GPGRT__RESTRICT stream,
                   char *_GPGRT__RESTRICT buf, int mode, size_t size);

void _gpgrt_set_binary(gpgrt_stream_t stream);

#include "estream-printf.h"

#if _WIN32
/* Prototypes for w32-estream.c.  */
struct cookie_io_functions_s _gpgrt_functions_w32_pollable;
int _gpgrt_w32_pollable_create(void *_GPGRT__RESTRICT *_GPGRT__RESTRICT cookie,
                               unsigned int modeflags,
                               struct cookie_io_functions_s next_functions,
                               void *next_cookie);
int _gpgrt_w32_poll(gpgrt_poll_t *fds, size_t nfds, int timeout);
#endif

gpgrt_b64state_t _gpgrt_b64dec_start(const char *title);
gpg_error_t _gpgrt_b64dec_proc(gpgrt_b64state_t state, void *buffer,
                               size_t length, size_t *r_nbytes);
gpg_error_t _gpgrt_b64dec_finish(gpgrt_b64state_t state);

#endif /*_GPGRT_GPGRT_INT_H*/
