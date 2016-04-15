AM_CPPFLAGS = \
	-DPACKAGE_DATA_DIR=\""$(pkgdatadir)"\" \
	$(CMUMBLE_CFLAGS)

AM_CFLAGS =\
	 -Wall\
	 -g

bin_PROGRAMS = cmumble

cmumble_SOURCES = \
	main.c \
	Mumble.pb-c.c \
	Mumble.proto \
	Mumble.pb-c.h \
	network.c \
	network.h \
	network_private.h \
	utils.h \
	utils.c \
	packet_header.h \
	network_common.h

cmumble_CFLAGS = -std=c11 \
	-Wall \
	-Wextra \
	-pedantic 

cmumble_LDFLAGS = 

cmumble_LDADD = $(CMUMBLE_LIBS) -lmbedtls -lmbedcrypto -lmbedx509

