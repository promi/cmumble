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
#include "packet_header.h"

G_BEGIN_DECLS
/* *INDENT-OFF* */
#define MUMBLE_TYPE_NETWORK mumble_network_get_type ()
G_DECLARE_DERIVABLE_TYPE (MumbleNetwork, mumble_network, MUMBLE, NETWORK,
                          GObject)
/* *INDENT-ON* */

typedef struct _MumbleNetworkClass
{
  GObjectClass parent_class;

  void (*connect) (MumbleNetwork *net, const gchar *server_name,
                   guint16 server_port, GError **err);

  void (*read_bytes) (MumbleNetwork *net, guint8 *buffer,
                      size_t buffer_length, GError **err);

  void (*write_bytes) (MumbleNetwork *net, const guint8 *buffer,
                       size_t buffer_length, GError **err);
} MumbleNetworkClass;

MumbleNetwork *mumble_network_new ();

void mumble_network_connect (MumbleNetwork *net,
                             const gchar *server_name,
                             guint16 server_port, GError **err);

void mumble_network_read_bytes (MumbleNetwork *net, guint8 *buffer,
                                size_t buffer_length, GError **err);

void mumble_network_read_packet_header (MumbleNetwork *net,
                                        MumblePacketHeader
                                        *packet_header, GError **err);

void mumble_network_write_bytes (MumbleNetwork *net,
                                 const guint8 *buffer,
                                 size_t buffer_length, GError **err);

void mumble_network_write_packet_header (MumbleNetwork *net,
                                         const MumblePacketHeader
                                         *packet_header, GError **err);

G_END_DECLS
#endif // __NETWORK_H__

