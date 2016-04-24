#!/bin/sh
indent \
-T gchar \
-T guint16 \
-T guint32 \
-T guint8 \
-T GApplication \
-T GApplicationClass \
-T GError \
-T GObject \
-T GObjectClass \
-T MumbleApplication \
-T MumbleApplicationClass \
-T MumbleMbedtlsNetwork \
-T MumbleMbedtlsNetworkClass \
-T MumbleNetwork \
-T MumbleNetworkClass \
-T MumblePacketHeader \
-nut "$@"
