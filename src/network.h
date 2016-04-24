/* -*- Mode: C; indent-tabs-mode: nil; c-basic-offset: 2; tab-width: 8 -*-  */
/*
    cmumble - Mumble client written in C
    Copyright (C) 2016 Prometheus <prometheus@unterderbruecke.de>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as
    published by the Free Software Foundation, either version 3 of the
    License, or (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef __NETWORK_H__
#define __NETWORK_H__

#include <glib.h>
#include <glib-object.h>
#include <gio/gio.h>

#include "packet_header.h"

#define MUMBLE_PACKET_TYPE__VERSION 0
#define MUMBLE_PACKET_TYPE__AUTHENTICATE 2
#define MUMBLE_PACKET_TYPE__PING 3

G_BEGIN_DECLS
/* *INDENT-OFF* */
#define MUMBLE_TYPE_NETWORK mumble_network_get_type ()
G_DECLARE_FINAL_TYPE (MumbleNetwork, mumble_network, MUMBLE, NETWORK, GObject)
/* *INDENT-ON* */

MumbleNetwork *mumble_network_new ();

void mumble_network_connect (MumbleNetwork *self,
                             const gchar *server_name,
                             guint16 server_port, GError **err);

void mumble_network_read_bytes (MumbleNetwork *self, guint8 *buffer,
                                size_t buffer_length, GError **err);

void mumble_network_read_packet_header (MumbleNetwork *self,
                                        MumblePacketHeader
                                        *packet_header, GError **err);

void mumble_network_read_packet_async (MumbleNetwork *self, GError **err);

typedef size_t (*mumble_message_get_packed_size) (const gpointer message);
typedef size_t (*mumble_message_pack) (const gpointer message, guint8 *out);

void mumble_network_write_packet (MumbleNetwork *self, guint16 type,
                                  mumble_message_get_packed_size
                                  get_packed_size, mumble_message_pack pack,
                                  gpointer message, GError **err);

G_END_DECLS
#endif // __NETWORK_H__

