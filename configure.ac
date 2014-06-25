dnl Initialize the autoconf process
AC_INIT([base-passwd], [3.5.33])
AC_CONFIG_SRCDIR([update-passwd.c])
AC_CONFIG_HEADER([config.h])
AC_PREFIX_DEFAULT([/usr])
AM_INIT_AUTOMAKE([-Wall foreign])

dnl Let's see if all programs we need are installed
AC_PROG_CC
AC_PROG_INSTALL

dnl Scan for things we need
AC_CHECK_FUNCS([putgrent])

dnl Finally output everything
AC_CONFIG_FILES([Makefile doc/Makefile man/Makefile])
AC_OUTPUT
