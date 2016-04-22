#!/bin/sh
indent -T MumbleNetwork -T GError -T MumblePacketHeader -T gchar -T guint8 \
-T guint16 -T guint32 -T GObject -T GObjectClass -T MumbleNetworkClass \
-T MumbleMbedtlsNetwork -T MumbleMbedtlsNetworkClass -nut "$@"
