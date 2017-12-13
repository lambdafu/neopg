
#define LOCALEDIR "/usr/share/neopg"
#define GNUPG_LOCALSTATEDIR "/usr/share/neopg"

#define GNUPG_BINDIR      "/usr/bin"
#define GNUPG_LIBEXECDIR  "/usr/libexec"
#define GNUPG_LIBDIR      "/usr/lib"
#define GNUPG_DATADIR     "/usr/share/neopg"
#define GNUPG_SYSCONFDIR  "/etc/neopg"

#define PACKAGE "neopg"
#define PACKAGE_GT PACKAGE

#define VERSION NEOPG_VERSION
#define PACKAGE_NAME "neopg"

/* libassuan */
#define USE_DESCRIPTOR_PASSING 1

/* npth */
#define HAVE_PSELECT 1
#define HAVE_CLOCK_GETTIME 1

/* libgcrypt */

/* List of available cipher algorithms */
#define LIBGCRYPT_CIPHERS "blowfish:cast5:des:aes:twofish:rfc2268:camellia:idea"

/* List of available digest algorithms */
#define LIBGCRYPT_DIGESTS "crc:md4:md5:rmd160:sha1:sha256:sha512:sha3:whirlpool"

/* List of available KDF algorithms */
#define LIBGCRYPT_KDFS "s2k:pkdf2:scrypt"

/* List of available public key cipher algorithms */
#define LIBGCRYPT_PUBKEY_CIPHERS "dsa:elgamal:rsa:ecc"

/* Defined if this module should be included */
#define USE_AES 1

#define USE_DES 1

/* Defined if this module should be included */
#define USE_BLOWFISH 1

/* Defined if this module should be included */
#define USE_CAMELLIA 1

/* Defined if this module should be included */
#define USE_CAST5 1

/* Defined if this module should be included */
#define USE_CRC 1

/* Defined if this module should be included */
#define USE_DSA 1

/* Defined if this module should be included */
#define USE_ECC 1

/* Defined if this module should be included */
#define USE_ELGAMAL 1

/* Defined if this module should be included */
#define USE_IDEA 1

/* Defined if this module should be included */
#define USE_MD4 1

/* Defined if this module should be included */
#define USE_MD5 1


/* Defined if this module should be included */
#define USE_RSA 1

/* Defined if this module should be included */
#define USE_SCRYPT 1

/* Defined if this module should be included */
#define USE_SHA1 1

/* Defined if this module should be included */
#define USE_SHA256 1

/* Defined if this module should be included */
#define USE_SHA3 1

/* Defined if this module should be included */
#define USE_SHA512 1

/* Defined if this module should be included */
#define USE_RFC2268 1

/* Defined if this module should be included */
#define USE_RMD160 1

/* Defined if this module should be included */
#define USE_TWOFISH 1

/* Defined if this module should be included */
#define USE_WHIRLPOOL 1

/* USE_CAPABILITIES */
#define HAVE_MLOCK 1

/* libgpg-error */

#define HAVE_GCC_ATTRIBUTE_ALIGNED 1
#define HAVE_INTMAX_T 1
#define HAVE_LOCALE_H 1
#define HAVE_LONG_DOUBLE 1
#define HAVE_LONG_LONG_INT 1
#define HAVE_MEMRCHR 1
#define HAVE_PTHREAD_RWLOCK 1
#define HAVE_PTRDIFF_T 1
#define HAVE_STDINT_H 1
#define HAVE_STDLIB_H 1
#define HAVE_SYS_SELECT_H 1
#define HAVE_SYS_STAT_H 1
#define HAVE_SYS_TIME_H 1
#define HAVE_SYS_TYPES_H 1
#define HAVE_UINTMAX_T 1
#define HAVE_VASPRINTF 1
#define REPLACEMENT_FOR_OFF_T "long"
/* #undef HAVE_W32_SYSTEM */
/* #undef HAVE_W64_SYSTEM */
/* #undef PTHREAD_IN_USE_DETECTION_HARD */
#define SIZEOF_INT 4
#define SIZEOF_LONG 8
#define SIZEOF_LONG_LONG 8
#define SIZEOF_PTHREAD_MUTEX_T 40
#define SIZEOF_TIME_T 8
#define SIZEOF_UNSIGNED_LONG 8
#define SIZEOF_VOID_P 8
#define STDC_HEADERS 1
#define TIME_WITH_SYS_TIME 1
#define USE_POSIX_THREADS 1
#define USE_POSIX_THREADS_WEAK 1
/* #undef USE_PTH_THREADS */
/* #undef USE_PTH_THREADS_WEAK */
/* #undef USE_SOLARIS_THREADS */
/* #undef USE_SOLARIS_THREADS_WEAK */

/* Enable extensions on AIX 3, Interix.  */
#ifndef _ALL_SOURCE
# define _ALL_SOURCE 1
#endif
/* Enable threading extensions on Solaris.  */
#ifndef _POSIX_PTHREAD_SEMANTICS
# define _POSIX_PTHREAD_SEMANTICS 1
#endif
/* Enable extensions on HP NonStop.  */
#ifndef _TANDEM_SOURCE
# define _TANDEM_SOURCE 1
#endif
/* Enable general extensions on Solaris.  */
#ifndef __EXTENSIONS__
# define __EXTENSIONS__ 1
#endif

/* #undef USE_WINDOWS_THREADS */
/* This makes sure libassuan gets CMSG macros to make descriptor
   passing work.  */
#ifdef __APPLE__
#define _DARWIN_C_SOURCE 1
#endif
#ifndef _DARWIN_USE_64_BIT_INODE
# define _DARWIN_USE_64_BIT_INODE 1
#endif
/* #undef _FILE_OFFSET_BITS */
/* #undef _LARGE_FILES */
/* #undef _MINIX */
/* #undef _POSIX_1_SOURCE */
/* #undef _POSIX_SOURCE */
#define _ESTREAM_PRINTF_REALLOC _gpgrt_realloc
#define _ESTREAM_PRINTF_EXTRA_INCLUDE "gpgrt-int.h"

/* libassuan */

#define HAVE_DECL_SYS_SIGLIST 1
/* #undef HAVE_DOSISH_SYSTEM */
#define HAVE_FCNTL_H 1
#define HAVE_FOPENCOOKIE 1
/* #undef HAVE_FUNOPEN */
#define HAVE_GETADDRINFO 1
/* #undef HAVE_GETPEEREID */
/* #undef HAVE_GETPEERUCRED */
#define HAVE_GETRLIMIT 1
#define HAVE_INET_PTON 1
#define HAVE_ISASCII 1
#define HAVE_LOCALE_H 1
/* #undef HAVE_LOCAL_PEEREID */
#define HAVE_MEMRCHR 1
#define HAVE_NANOSLEEP 1
#define HAVE_STAT 1
#define HAVE_STDINT_H 1
#define HAVE_STDLIB_H 1
#define HAVE_STPCPY 1
#define HAVE_SYS_SELECT_H 1
#define HAVE_SYS_SOCKET_H 1
#define HAVE_SYS_STAT_H 1
#define HAVE_SYS_TIME_H 1
#define HAVE_SYS_TYPES_H 1
#define HAVE_SYS_UIO_H 1
/* #undef HAVE_UCRED_H */
#define HAVE_UINTPTR_T 1
/* #undef HAVE_W32_SYSTEM */
/* #undef HAVE_W64_SYSTEM */
/* #undef HAVE_WINSOCK2_H */
/* #undef HAVE_WS2TCPIP_H */
#define STDC_HEADERS 1
#define USE_DESCRIPTOR_PASSING 1
/* #undef _DARWIN_C_SOURCE */
/* #undef _POSIX_1_SOURCE */
/* #undef _POSIX_SOURCE */
/* #undef _XOPEN_SOURCE */
/* #undef _XOPEN_SOURCE_EXTENDED */
#define __EXTENSIONS__ 1

/* npth */

#define HAVE_CLOCK_GETTIME 1
#define HAVE_GETTIMEOFDAY 1
#define HAVE_PSELECT 1
#define HAVE_PTHREAD 1
#define HAVE_PTHREAD_ATFORK 1
#ifndef __APPLE__
#define HAVE_PTHREAD_MUTEX_TIMEDLOCK 1
#define HAVE_PTHREAD_RWLOCK_TIMEDRDLOCK 1
#define HAVE_PTHREAD_RWLOCK_TIMEDWRLOCK 1
#endif
#define HAVE_PTHREAD_RWLOCK_RDLOCK 1
#define HAVE_PTHREAD_RWLOCK_TRYRDLOCK 1
#define HAVE_PTHREAD_RWLOCK_TRYWRLOCK 1
#define HAVE_PTHREAD_RWLOCK_WRLOCK 1
#define HAVE_SELECT 1
#define HAVE_SIGNAL_H 1
#define HAVE_STDINT_H 1
#define HAVE_STDLIB_H 1
#define HAVE_SYS_SELECT_H 1
#define HAVE_SYS_SOCKET_H 1
#define HAVE_SYS_STAT_H 1
#define HAVE_SYS_TIME_H 1
#define HAVE_SYS_TYPES_H 1
#define HAVE_TIME_H 1
/* #undef HAVE_W32_SYSTEM */
/* #undef HAVE_W64_SYSTEM */
/* #undef HAVE_WINSOCK2_H */
/* #undef HAVE_WS2TCPIP_H */
#define STDC_HEADERS 1
/* #undef _MINIX */
/* #undef _POSIX_1_SOURCE */
/* #undef _POSIX_SOURCE */
#ifndef _REENTRANT
# define _REENTRANT 1
#endif


/* gnupg */

/* #undef BIG_ENDIAN_HOST */
/* #undef BIND_8_COMPAT */
/* #undef DEFAULT_TRUST_STORE_FILE */
#define DIRMNGR_DEFAULT_KEYSERVER "hkps://hkps.pool.sks-keyservers.net"
#define DIRMNGR_DISP_NAME "DirMngr"
#define DIRMNGR_INFO_NAME "DIRMNGR_INFO"
#define DIRMNGR_NAME "dirmngr"
#define DIRMNGR_SOCK_NAME "S.dirmngr"
/* Define to disable regular expression support */
/* #undef DISABLE_REGEX */
/* Define to include smartcard support */
#define ENABLE_CARD_SUPPORT 1
/* Define to enable SELinux support */
/* #undef ENABLE_SELINUX_HACKS */
/* The executable file extension, if any */
#define EXEEXT ""
#define GNUPG_NAME "NeoPG"
/* #undef GNUPG_REGISTRY_DIR */
#define GPGCONF_NAME "neopgconf"
#define GPGEXT_GPG "npg"
#define GPGSM_DISP_NAME "NeoPGSM"
#define GPGSM_NAME "neopgsm"
#define GPGTAR_NAME "neopgtar"
#define GPG_AGENT_NAME "neopg-agent"
#define GPG_DISP_NAME "NeoPG"
#define GPG_NAME "neopg"
#define GPG_USE_AES128 1
#define GPG_USE_AES192 1
#define GPG_USE_AES256 1
#define GPG_USE_BLOWFISH 1
#define GPG_USE_CAMELLIA128 1
#define GPG_USE_CAMELLIA192 1
#define GPG_USE_CAMELLIA256 1
#define GPG_USE_CAST5 1
#define GPG_USE_ECDH 1
#define GPG_USE_EDDSA 1
#define GPG_USE_IDEA 1
#define GPG_USE_MD5 1
#define GPG_USE_RMD160 1
#define GPG_USE_RSA 1
#define GPG_USE_SHA224 1
#define GPG_USE_SHA384 1
#define GPG_USE_SHA512 1
#define GPG_USE_TWOFISH 1
/* #undef HAVE_ANDROID_SYSTEM */
/* #undef HAVE_BROKEN_TTYNAME */
/* #undef HAVE_BYTE_TYPEDEF */
#define HAVE_CLOCK_GETTIME 1
#define HAVE_CTERMID 1
#define HAVE_DECL_GETPAGESIZE 1
#define HAVE_DECL_SYS_SIGLIST 1
/* #undef HAVE_DIRECT_H */
/* #undef HAVE_DOPRNT */
/* #undef HAVE_DOSISH_SYSTEM */
/* #undef HAVE_DRIVE_LETTERS */
#define HAVE_FCNTL 1
#define HAVE_FORK 1
#define HAVE_FSEEKO 1
#define HAVE_FSYNC 1
#define HAVE_FTRUNCATE 1
#define HAVE_GETADDRINFO 1
#define HAVE_GETENV 1
#define HAVE_GETOPT_H 1
#define HAVE_GETPAGESIZE 1
/* #undef HAVE_GETPEERUCRED */
#define HAVE_GETPWNAM 1
#define HAVE_GETPWUID 1
#define HAVE_GETRLIMIT 1
#define HAVE_GETRUSAGE 1
#define HAVE_GETTIMEOFDAY 1
#define HAVE_GMTIME_R 1
#define HAVE_INET_NTOP 1
#define HAVE_INET_PTON 1
#ifndef __APPLE__
  #define HAVE_INOTIFY_INIT 1
#endif
#define HAVE_ISASCII 1
#define HAVE_LANGINFO_CODESET 1
#define HAVE_LANGINFO_H 1
/* #undef HAVE_LBER */
#define HAVE_LC_MESSAGES 1
/* #undef HAVE_LIBREADLINE */
#define HAVE_LIBUSB 1
#define HAVE_LOCALE_H 1
/* #undef HAVE_MEMICMP */
#define HAVE_MEMRCHR 1
#define HAVE_MMAP 1
#define HAVE_NANOSLEEP 1
#define HAVE_NL_LANGINFO 1
#define HAVE_NPTH 1
#define HAVE_PIPE 1
#define HAVE_PTY_H 1
#define HAVE_PWD_H 1
#define HAVE_SETLOCALE 1
#define HAVE_SETRLIMIT 1
#define HAVE_SIGNAL_H 1
#define HAVE_STAT 1
#define HAVE_STDINT_H 1
#define HAVE_STDLIB_H 1
#define HAVE_STPCPY 1
#define HAVE_STRCHR 1
#define HAVE_STRFTIME 1
/* #undef HAVE_STRICMP */
/* #undef HAVE_STRLWR */
#define HAVE_STRUCT_SIGACTION 1
/* #undef HAVE_STRUCT_SOCKPEERCRED_PID */
/* #undef HAVE_STRUCT_UCRED_CR_PID */
#define HAVE_STRUCT_UCRED_PID 1
#define HAVE_SYSTEM_RESOLVER 1
/* #undef HAVE_SYS_MKDEV_H */
#define HAVE_SYS_SELECT_H 1
#define HAVE_SYS_SOCKET_H 1
#define HAVE_SYS_STAT_H 1
#define HAVE_SYS_SYSMACROS_H 1
#define HAVE_SYS_TYPES_H 1
#define HAVE_TCGETATTR 1
#define HAVE_TERMIOS_H 1
#define HAVE_TERMIO_H 1
#define HAVE_TIMES 1
#define HAVE_TTYNAME 1
/* #undef HAVE_U16_TYPEDEF */
/* #undef HAVE_U32_TYPEDEF */
/* #undef HAVE_UCRED_H */
#define HAVE_ULONG_TYPEDEF 1
/* #undef HAVE_UNSIGNED_TIME_T */
#define HAVE_USHORT_TYPEDEF 1
/* #undef HAVE_UTIL_H */
#define HAVE_UTMP_H 1
#define HAVE_VFORK 1
/* #undef HAVE_VFORK_H */
#define HAVE_VPRINTF 1
/* Defined if we run on a W32 API based system */
/* #undef HAVE_W32_SYSTEM */
#define HAVE_WAIT4 1
#define HAVE_WAITPID 1
/* #undef HAVE_WINSOCK2_H */
#define HAVE_WORKING_FORK 1
#define HAVE_WORKING_VFORK 1
/* #undef HAVE_WS2TCPIP_H */
#define HAVE_ZIP 1
#define LITTLE_ENDIAN_HOST 1
/* #undef MKDIR_TAKES_ONE_ARG */
/* #undef NEED_LBER_H */
/* #undef NO_EXEC */
/* #undef NO_TRUST_MODELS */
#define PK_UID_CACHE_SIZE 4096
#define SCDAEMON_DISP_NAME "SCDaemon"
#define SCDAEMON_NAME "scdaemon"
#define SCDAEMON_SOCK_NAME "S.scdaemon"
#define SECMEM_BUFFER_SIZE 32768
#define SIZEOF_TIME_T 8
#define SIZEOF_UNSIGNED_INT 4
#define SIZEOF_UNSIGNED_LONG 8
#define SIZEOF_UNSIGNED_LONG_LONG 8
#define SIZEOF_UNSIGNED_SHORT 2
#define STDC_HEADERS 1
#define TIME_WITH_SYS_TIME 1
#define USE_NPTH 1
/* #undef USE_ONLY_8DOT3 */
/* #undef _DARWIN_C_SOURCE */
#ifndef _DARWIN_USE_64_BIT_INODE
# define _DARWIN_USE_64_BIT_INODE 1
#endif
/* #undef _FILE_OFFSET_BITS */
/* #undef _LARGEFILE_SOURCE */
/* #undef _LARGE_FILES */
/* #undef _POSIX_1_SOURCE */
/* #undef _POSIX_SOURCE */

/* Now to separate file name parts.
   Please note that the string version must not contain more
   than one character because the code assumes strlen()==1 */
#ifdef HAVE_DOSISH_SYSTEM
#define DIRSEP_C '\\'
#define DIRSEP_S "\\"
#define EXTSEP_C '.'
#define EXTSEP_S "."
#define PATHSEP_C ';'
#define PATHSEP_S ";"
#define EXEEXT_S ".exe"
#else
#define DIRSEP_C '/'
#define DIRSEP_S "/"
#define EXTSEP_C '.'
#define EXTSEP_S "."
#define PATHSEP_C ':'
#define PATHSEP_S ":"
#define EXEEXT_S ""
#endif

#define SAFE_VERSION VERSION
#define SAFE_VERSION_DOT  '.'
#define SAFE_VERSION_DASH '-'

/* Some global constants. */
#ifdef HAVE_DOSISH_SYSTEM
# ifdef HAVE_DRIVE_LETTERS
#  define GNUPG_DEFAULT_HOMEDIR "c:/neopg"
# else
#  define GNUPG_DEFAULT_HOMEDIR "/neopg"
# endif
#elif defined(__VMS)
#define GNUPG_DEFAULT_HOMEDIR "/SYS$LOGIN/neopg"
#else
#define GNUPG_DEFAULT_HOMEDIR "~/.neopg"
#endif
#define GNUPG_PRIVATE_KEYS_DIR  "private-keys-v1.d"
#define GNUPG_OPENPGP_REVOC_DIR "openpgp-revocs.d"

/* For some systems (DOS currently), we hardcode the path here.  For
   POSIX systems the values are constructed by the Makefiles, so that
   the values may be overridden by the make invocations; this is to
   comply with the GNU coding standards.  Note that these values are
   only defaults.  */
#ifdef HAVE_DOSISH_SYSTEM
# ifdef HAVE_DRIVE_LETTERS
#  define GNUPG_BINDIR      "c:\\neopg"
#  define GNUPG_LIBEXECDIR  "c:\\neopg"
#  define GNUPG_LIBDIR      "c:\\neopg"
#  define GNUPG_DATADIR     "c:\\neopg"
#  define GNUPG_SYSCONFDIR  "c:\\neopg"
# else
#  define GNUPG_BINDIR      "\\neopg"
#  define GNUPG_LIBEXECDIR  "\\neopg"
#  define GNUPG_LIBDIR      "\\neopg"
#  define GNUPG_DATADIR     "\\neopg"
#  define GNUPG_SYSCONFDIR  "\\neopg"
# endif
#endif

/* Derive some other constants. */
#if !(defined(HAVE_FORK) && defined(HAVE_PIPE) && defined(HAVE_WAITPID))
#define EXEC_TEMPFILE_ONLY
#endif


/* We didn't define endianness above, so get it from OS macros.  This
   is intended for making fat binary builds on OS X. */
#if !defined(BIG_ENDIAN_HOST) && !defined(LITTLE_ENDIAN_HOST)
#if defined(__BIG_ENDIAN__)
#define BIG_ENDIAN_HOST 1
#elif defined(__LITTLE_ENDIAN__)
#define LITTLE_ENDIAN_HOST 1
#else
#error "No endianness found"
#endif
#endif


#define USE_RNDLINUX 1
