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

#include <stdio.h>
#include <arpa/inet.h>
#include <string.h>

#include "error.h"
#include "network.h"

typedef struct _MumbleNetwork
{
  GObject parent;

  GSocketClient *socket_client;
  GSocketConnection *connection;
} MumbleNetwork;

/* *INDENT-OFF* */
G_DEFINE_TYPE (MumbleNetwork, mumble_network, G_TYPE_OBJECT)
/* *INDENT-ON* */

static const char pers[] = "cmumble";

void mumble_network_socket_event (GSocketClient *client,
                                  GSocketClientEvent event,
                                  GSocketConnectable *connectable,
                                  GIOStream *connection, gpointer user_data);

static void mumble_network_finalize (GObject *object);

static void
mumble_network_class_init (MumbleNetworkClass *klass)
{
  GObjectClass *gobject_class = G_OBJECT_CLASS (klass);

  gobject_class->finalize = mumble_network_finalize;
}

static void
mumble_network_init (MumbleNetwork *self)
{
  self->socket_client = g_socket_client_new ();
  g_socket_client_set_tls (self->socket_client, TRUE);
  g_signal_connect (self->socket_client, "event",
                    G_CALLBACK (mumble_network_socket_event), self);
}

static void
mumble_network_finalize (GObject *object)
{
  MumbleNetwork *self = MUMBLE_NETWORK (object);
  g_object_unref (self->connection);
  g_object_unref (self->socket_client);

  GObjectClass *parent_class = G_OBJECT_CLASS (mumble_network_parent_class);
  (*parent_class->finalize) (object);
}

MumbleNetwork *
mumble_network_new (void)
{
  return g_object_new (MUMBLE_TYPE_NETWORK, NULL);
}

gboolean
mumble_network_accept_certificate (G_GNUC_UNUSED
                                   GTlsConnection *conn,
                                   G_GNUC_UNUSED
                                   GTlsCertificate *peer_cert,
                                   G_GNUC_UNUSED
                                   GTlsCertificateFlags
                                   errors, G_GNUC_UNUSED gpointer user_data)
{
  if (errors != 0)
  {
    // Ignore invalid certificates for now, but at least warn the user
    printf ("WARNING: Server does not have a strong certificate\n");
  }
  return TRUE;
}

void
mumble_network_socket_event (G_GNUC_UNUSED GSocketClient
                             *client,
                             GSocketClientEvent event,
                             G_GNUC_UNUSED
                             GSocketConnectable
                             *connectable,
                             GIOStream *connection, gpointer user_data)
{
  if (event == G_SOCKET_CLIENT_TLS_HANDSHAKING)
    {
      GTlsClientConnection *tls_conn = G_TLS_CLIENT_CONNECTION (connection);
      // g_tls_connection_set_certificate ();
      g_signal_connect (tls_conn, "accept_certificate",
                        G_CALLBACK
                        (mumble_network_accept_certificate), user_data);
    }
}

void
mumble_network_connect (MumbleNetwork *self,
                        const gchar *server_name,
                        guint16 server_port, GError **err)
{
  g_return_if_fail (self != NULL);
  g_return_if_fail (err == NULL || *err == NULL);
  GSocketConnectable *address =
    g_network_address_new (server_name, server_port);
  self->connection =
    g_socket_client_connect (self->socket_client, address, NULL, err);
  g_object_unref (address);
}

void
mumble_network_read_bytes (MumbleNetwork *self,
                           guint8 *buffer, size_t length, GError **err)
{
  g_return_if_fail (self != NULL);
  g_return_if_fail (buffer != NULL);
  g_return_if_fail (length > 0);
  g_return_if_fail (err == NULL || *err == NULL);

  GIOStream *iostream = G_IO_STREAM (self->connection);

  GInputStream *istream = g_io_stream_get_input_stream (iostream);
  g_input_stream_read_all (istream, buffer, length, NULL, NULL, err);
}

void
mumble_network_write_bytes (MumbleNetwork *self,
                            const guint8 *buffer, size_t length, GError **err)
{
  g_return_if_fail (self != NULL);
  g_return_if_fail (buffer != NULL);
  g_return_if_fail (length > 0);
  g_return_if_fail (err == NULL || *err == NULL);

  GIOStream *iostream = G_IO_STREAM (self->connection);

  GOutputStream *ostream = g_io_stream_get_output_stream (iostream);
  g_output_stream_write_all (ostream, buffer, length, NULL, NULL, err);
}

void
mumble_network_read_packet_header (MumbleNetwork *self,
                                   MumblePacketHeader
                                   *packet_header, GError **err)
{
  g_return_if_fail (self != NULL);
  g_return_if_fail (packet_header != NULL);
  g_return_if_fail (err == NULL || *err == NULL);
  const size_t buffer_length = 6;
  guint8 *buffer = g_malloc0 (buffer_length);
  if (buffer == NULL)
    {
      g_set_error (err, MUMBLE_NETWORK_ERROR,
                   MUMBLE_NETWORK_ERROR_FAIL, "calloc failed");
      return;
    }

  GError *tmp_error = NULL;
  mumble_network_read_bytes (self, buffer, buffer_length, &tmp_error);
  if (tmp_error != NULL)
    {
      g_propagate_error (err, tmp_error);
      g_free (buffer);
      return;
    }

  packet_header->type = ntohs (*(uint16_t *) buffer);
  packet_header->length = ntohl (*(uint32_t *) (buffer + 2));
  g_free (buffer);
}

void
mumble_network_write_packet_header (MumbleNetwork *self,
                                    const MumblePacketHeader
                                    *packet_header, GError **err)
{
  g_return_if_fail (self != NULL);
  g_return_if_fail (packet_header != NULL);
  g_return_if_fail (err == NULL || *err == NULL);
  const int buffer_length = 6;
  guint8 *buffer = g_malloc0 (buffer_length);
  if (buffer == NULL)
    {
      g_set_error (err, MUMBLE_NETWORK_ERROR,
                   MUMBLE_NETWORK_ERROR_FAIL, "calloc failed");
      return;
    }

  *(uint16_t *) buffer = htons (packet_header->type);
  *(uint32_t *) (buffer + 2) = htonl (packet_header->length);
  GError *tmp_error = NULL;
  mumble_network_write_bytes (self, (const guint8 *) buffer,
                              buffer_length, &tmp_error);
  if (tmp_error != NULL)
    {
      g_propagate_error (err, tmp_error);
    }

  g_free (buffer);
}

void
mumble_network_write_packet (MumbleNetwork *self,
                             guint16 type,
                             mumble_message_get_packed_size
                             get_packed_size,
                             mumble_message_pack pack,
                             gpointer message, GError **err)
{
  g_return_if_fail (self != NULL);
  g_return_if_fail (get_packed_size != NULL);
  g_return_if_fail (pack != NULL);
  g_return_if_fail (message != NULL);
  g_return_if_fail (err == NULL || *err == NULL);
  MumblePacketHeader header = {
    type, get_packed_size (message)
  };
  GError *tmp_error = NULL;
  mumble_network_write_packet_header (self, &header, &tmp_error);
  if (tmp_error != NULL)
    {
      g_propagate_error (err, tmp_error);
      return;
    }

  // Payload could be empty (i.e. PING message without any actual data filled)
  // That's not an error, only just send the header and no payload in that case
  if (header.length > 0)
    {
      guint8 *buffer = g_malloc0 (header.length);
      if (buffer == NULL)
        {
          g_set_error (err, MUMBLE_NETWORK_ERROR,
                       MUMBLE_NETWORK_ERROR_ALLOCATION_FAIL,
                       "g_malloc failed");
          return;
        }

      pack (message, buffer);
      mumble_network_write_bytes (self, buffer, header.length, &tmp_error);
      if (tmp_error != NULL)
        {
          g_propagate_error (err, tmp_error);
        }
      g_free (buffer);
    }
}
