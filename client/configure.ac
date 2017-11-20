#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT(l2tp_client, 0.3.0, development@wlan-si.net)
AM_INIT_AUTOMAKE([-Wall -Werror foreign subdir-objects])
AC_CONFIG_SRCDIR([l2tp_client.c])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([Makefile])

# Checks for programs.
AC_PROG_CC

# Checks for libraries.

# Checks for header files.
AC_HEADER_RESOLV
AC_CHECK_HEADERS([arpa/inet.h fcntl.h netdb.h netinet/in.h stdint.h stdlib.h string.h sys/ioctl.h sys/socket.h sys/time.h syslog.h unistd.h])

PKG_CHECK_MODULES([LIBNL], [libnl-3.0 libnl-genl-3.0],
   [AC_DEFINE([HAVE_LIBNL], [1], [Use libnl])],
   [PKG_CHECK_MODULES([LIBNL_TINY], [libnl-tiny],
       [AC_DEFINE([HAVE_LIBNL_TINY], [1], [Use libnl-tiny])
    ])
])

AC_ARG_WITH([libasyncns], AS_HELP_STRING([--without-libasyncns], [Use bundled libasyncns (default: no)]))

AS_IF([test "x$with_libasyncns" != "xno"], [
  PKG_CHECK_MODULES([LIBASYNCNS], [libasyncns], [HAVE_LIBASYNCNS=1],[HAVE_LIBASYNCNS=0])
])

AS_IF([test "x$HAVE_LIBASYNCNS" = x1], [AC_DEFINE([HAVE_LIBASYNCNS], [1], [Use shared libasyncns])])
AM_CONDITIONAL([USE_LIBASYNCNS], [test "x$HAVE_LIBASYNCNS" = x1])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT8_T

# Checks for library functions.
AC_FUNC_FORK
AC_FUNC_MALLOC
AC_CHECK_FUNCS([clock_gettime memset select socket strchr strdup strndup strtol strtoul])

AC_OUTPUT
