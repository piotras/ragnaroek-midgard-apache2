dnl Process this file with autoconf to produce a configure script.
AC_INIT([midgard-apache2],[8.10.0])
AC_PREREQ(2.50)
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_SRCDIR([midgard-apache2.c])
AC_CONFIG_HEADERS([config.h])

AM_INIT_AUTOMAKE([-Wno-portability -Wall])
AM_MAINTAINER_MODE

dnl Checks for programs.
AC_DISABLE_STATIC
AM_PROG_LIBTOOL

dnl Piotras: keep it here for daily tarballs
PATH=${PATH}:/usr/local/bin

dnl Check for pkg-config
AC_ARG_WITH([pkg-config],
	AC_HELP_STRING([--with-pkg-config=PATH], [Location of the pkg-config executable]),
	[_AP_PKGCONFIG="$withval"],
	[AC_PATH_PROG([_AP_PKGCONFIG],["pkg-config"])])
MIDGARD_CFLAGS=`"$_AP_PKGCONFIG" --cflags midgard`
MIDGARD_LIBS=`"$_AP_PKGCONFIG" --libs midgard`
AC_SUBST([MIDGARD_CFLAGS])
AC_SUBST([MIDGARD_LIBS])

dnl Check for apxs
AC_ARG_WITH([apxs],
            AC_HELP_STRING([--with-apxs=PATH], [Location of the apxs program]),
            [APXS="$withval"],
            [AC_PATH_PROG([APXS],["apxs"])])
test -x "$APXS" || AC_MSG_ERROR([apxs not found, use --with-apxs]);
APXS_CFLAGS=""
for apxs_query in SHLTCFLAGS CFLAGS NOTEST_CPPFLAGS EXTRA_CPPFLAGS EXTRA_CFLAGS
do
    apxs_query_cflags=`"$APXS" -q $apxs_query`
    APXS_CFLAGS="$APXS_CFLAGS $apxs_query_cflags"
done
APR_INCLUDEDIR=`"$APXS" -q APR_INCLUDEDIR`
test -n "$APR_INCLUDEDIR" && APXS_CFLAGS="$APXS_CFLAGS -I$APR_INCLUDEDIR"
APXS_INCLUDEDIR=`"$APXS" -q INCLUDEDIR`
APXS_LIBEXECDIR=`"$APXS" -q LIBEXECDIR`
AC_SUBST([APXS_CFLAGS])
AC_SUBST([APXS_INCLUDEDIR])
AC_SUBST([APXS_LIBEXECDIR])

APR_1_CFLAGS="`apr-1-config --cflags --cppflags --includes` -I/usr/include/apr-1"
APR_1_LDLAGS=`apr-1-config --link-libtool --libs`
AC_SUBST([APR_1_CFLAGS])
AC_SUBST([APR_1_LDFLAGS])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
