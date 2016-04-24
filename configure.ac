AC_INIT(cmumble, 0.1)

AC_CONFIG_HEADERS([config.h])

AM_INIT_AUTOMAKE([1.11 foreign])

AM_SILENT_RULES([yes])

AC_PROG_CC

dnl LT_INIT

PKG_CHECK_MODULES(CMUMBLE, [glib-2.0 gobject-2.0 gio-2.0 libprotobuf-c ])

GLIB_GSETTINGS

AC_OUTPUT([
	Makefile
	src/Makefile
])

