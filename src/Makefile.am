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
	packet_header.h \
	error.h \
	indent.sh \
	error.c \
	com.github.promi.cmumble.gschema.xml \
	application.c \
	application.h \
	packet_data_stream.c \
	packet_data_stream.h

cmumble_CFLAGS = -std=c11 \
	-Wall \
	-Wextra \
	-pedantic 

cmumble_LDFLAGS = 

cmumble_LDADD = $(CMUMBLE_LIBS)

gsettings_SCHEMAS = com.github.promi.cmumble.gschema.xml

@GSETTINGS_RULES@

