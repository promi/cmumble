AC_INIT(cmumble, 0.1)

AC_CONFIG_HEADERS([config.h])

AM_INIT_AUTOMAKE([1.11 foreign])

AM_SILENT_RULES([yes])

AC_PROG_CC

dnl LT_INIT

AC_CHECK_LIB([mbedtls], [mbedtls_ssl_init], [ ], [
	echo "libmbedtls not found"
	exit -1
])

AC_CHECK_LIB([mbedcrypto], [mbedtls_sha256_init], [ ], [
	echo "libmbedcrypto not found"
	exit -1
])

AC_CHECK_LIB([mbedx509], [mbedtls_x509_crt_init], [ ], [
	echo "libmbedx509 not found"
	exit -1
])

PKG_CHECK_MODULES(CMUMBLE, [glib-2.0 gobject-2.0 libprotobuf-c ])

AC_OUTPUT([
	Makefile
	src/Makefile
])
