## Process this file with automake to produce Makefile.in

AM_CFLAGS=-I@APXS_INCLUDEDIR@ @APXS_CFLAGS@ @APR_1_CFLAGS@ @MIDGARD_CFLAGS@
AM_LDFLAGS=@APR_1_LDFLAGS@ @MIDGARD_LIBS@ 

moduledir=@APXS_LIBEXECDIR@

module_LTLIBRARIES = midgard-apache2.la
midgard_apache2_la_SOURCES = midgard-apache2.c
midgard_apache2_la_LDFLAGS = -module @MIDGARD_LIBS@

phpdir=@APXS_LIBEXECDIR@

php_DATA = midgard-root.php midgard-root-nommp.php

EXTRA_DIST = midgard-root.php \
	midgard-root-nommp.php 
