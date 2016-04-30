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

typedef enum _MumbleMessageType
{
  MUMBLE_MESSAGE_TYPE__VERSION = 0,
  MUMBLE_MESSAGE_TYPE__UDP_TUNNEL = 1,
  MUMBLE_MESSAGE_TYPE__AUTHENTICATE = 2,
  MUMBLE_MESSAGE_TYPE__PING = 3,
  MUMBLE_MESSAGE_TYPE__REJECT = 4,
  MUMBLE_MESSAGE_TYPE__SERVER_SYNC = 5,
  MUMBLE_MESSAGE_TYPE__CHANNEL_REMOVE = 6,
  MUMBLE_MESSAGE_TYPE__CHANNEL_STATE = 7,
  MUMBLE_MESSAGE_TYPE__USER_REMOVE = 8,
  MUMBLE_MESSAGE_TYPE__USER_STATE = 9,
  MUMBLE_MESSAGE_TYPE__BAN_LIST = 10,
  MUMBLE_MESSAGE_TYPE__TEXT_MESSAGE = 11,
  MUMBLE_MESSAGE_TYPE__PERMISSION_DENIED = 12,
  MUMBLE_MESSAGE_TYPE__ACL = 13,
  MUMBLE_MESSAGE_TYPE__QUERY_USERS = 14,
  MUMBLE_MESSAGE_TYPE__CRYPT_SETUP = 15,
  MUMBLE_MESSAGE_TYPE__CONTEXT_ACTION_MODIFY = 16,
  MUMBLE_MESSAGE_TYPE__CONTEXT_ACTION = 17,
  MUMBLE_MESSAGE_TYPE__USER_LIST = 18,
  MUMBLE_MESSAGE_TYPE__VOICE_TARGET = 19,
  MUMBLE_MESSAGE_TYPE__PERMISSION_QUERY = 20,
  MUMBLE_MESSAGE_TYPE__CODEC_VERSION = 21,
  MUMBLE_MESSAGE_TYPE__USER_STATS = 22,
  MUMBLE_MESSAGE_TYPE__REQUEST_BLOB = 23,
  MUMBLE_MESSAGE_TYPE__SERVER_CONFIG = 24,
  MUMBLE_MESSAGE_TYPE__SUGGEST_CONFIG = 25
} MumbleMessageType;

/* *INDENT-OFF* */
G_BEGIN_DECLS
#define MUMBLE_TYPE_NETWORK mumble_network_get_type ()
G_DECLARE_FINAL_TYPE (MumbleNetwork, mumble_network, MUMBLE, NETWORK, GObject)
/* *INDENT-ON* */

typedef size_t (*mumble_message_get_packed_size) (const gpointer message);

typedef size_t (*mumble_message_pack) (const gpointer message, guint8 *out);

typedef gboolean (*mumble_read_callback) (MumbleNetwork *self,
                                          MumbleMessageType type, guint8 *data,
                                          guint32 length, gpointer user_data);

MumbleNetwork *mumble_network_new ();

void mumble_network_connect (MumbleNetwork *self,
                             const gchar *server_name,
                             guint16 server_port,
                             GTlsCertificate *certificate, GError **err);

void mumble_network_read_packet_async (MumbleNetwork *self,
                                       mumble_read_callback cb,
                                       gpointer user_data,
                                       GError **err);

void mumble_network_write_packet (MumbleNetwork *self, guint16 type,
                                  mumble_message_get_packed_size
                                  get_packed_size, mumble_message_pack pack,
                                  gpointer message, GError **err);

/* *INDENT-OFF* */
G_END_DECLS
/* *INDENT-ON* */

#endif // __NETWORK_H__
