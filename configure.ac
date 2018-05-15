AC_INIT(dropwatch,1.5)
AC_PREREQ(2.12)dnl
AM_CONFIG_HEADER(config.h)

AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE([foreign] [subdir-objects])
AM_PROG_LIBTOOL
AC_SUBST(LIBTOOL_DEPS)

AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_AWK

AC_CHECK_FUNCS(getopt_long)

PKG_CHECK_MODULES([LIBNL3], [libnl-3.0], [], [AC_MSG_ERROR([libnl-3.0 is required])])

AC_OUTPUT(Makefile src/Makefile doc/Makefile tests/Makefile)

AC_MSG_NOTICE()
AC_MSG_NOTICE([dropwatch Version:     $VERSION])
AC_MSG_NOTICE([Target:                 $target])
AC_MSG_NOTICE([Installation prefix:    $prefix])
AC_MSG_NOTICE([Compiler:               $CC])
AC_MSG_NOTICE([Compiler flags: $CFLAGS])
