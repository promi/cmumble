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

#include <arpa/inet.h>
#include <string.h>
#include <mbedtls/net.h>
#include <mbedtls/ssl.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/debug.h>

#include "error.h"
#include "network.h"


/* *INDENT-OFF* */
G_DEFINE_TYPE (MumbleNetwork, mumble_network, G_TYPE_OBJECT)
/* *INDENT-ON* */

static const char pers[] = "cmumble";

static void mumble_network_finalize (GObject *object);

static void
mumble_network_class_init (MumbleNetworkClass *klass)
{
  GObjectClass *gobject_class = G_OBJECT_CLASS (klass);

  gobject_class->finalize = mumble_network_finalize;
}

static void
mumble_network_init (G_GNUC_UNUSED MumbleNetwork *net)
{

}

static void
mumble_network_finalize (GObject *object)
{
  GObjectClass *parent_class = G_OBJECT_CLASS (mumble_network_parent_class);
  (*parent_class->finalize) (object);
}

/*
MumbleNetwork *
mumble_network_new (void)
{
  return g_object_new (MUMBLE_TYPE_NETWORK, NULL);
}
*/

void
mumble_network_connect (MumbleNetwork *net, const gchar *server_name,
                        const gchar *server_port, GError **err)
{
  MumbleNetworkClass *klass;
  klass = MUMBLE_NETWORK_GET_CLASS (net);
  klass->connect (net, server_name, server_port, err);
}

void
mumble_network_read_bytes (MumbleNetwork *net, guint8 *buffer,
                           size_t length, GError **err)
{
  MumbleNetworkClass *klass;
  klass = MUMBLE_NETWORK_GET_CLASS (net);
  klass->read_bytes (net, buffer, length, err);
}

void
mumble_network_write_bytes (MumbleNetwork *net, const guint8 *buffer,
                            size_t length, GError **err)
{
  MumbleNetworkClass *klass;
  klass = MUMBLE_NETWORK_GET_CLASS (net);
  klass->write_bytes (net, buffer, length, err);
}

void
mumble_network_read_packet_header (MumbleNetwork *net,
                                   MumblePacketHeader *packet_header,
                                   GError **err)
{
  g_return_if_fail (net != NULL);
  g_return_if_fail (packet_header != NULL);
  g_return_if_fail (err == NULL || *err == NULL);

  const size_t buffer_length = 6;
  guint8 *buffer = calloc (1, buffer_length);
  if (buffer == NULL)
    {
      g_set_error (err, MUMBLE_NETWORK_ERROR, MUMBLE_NETWORK_ERROR_FAIL,
                   "calloc failed");
      return;
    }

  GError *tmp_error = NULL;
  mumble_network_read_bytes (net, buffer, buffer_length, &tmp_error);
  if (tmp_error != NULL)
    {
      g_propagate_error (err, tmp_error);
      free (buffer);
      return;
    }

  packet_header->type = ntohs (*(uint16_t *) buffer);
  packet_header->length = ntohl (*(uint32_t *) (buffer + 2));

  free (buffer);
}

void
mumble_network_write_packet_header (MumbleNetwork *net,
                                    const MumblePacketHeader *packet_header,
                                    GError **err)
{
  g_return_if_fail (net != NULL);
  g_return_if_fail (packet_header != NULL);
  g_return_if_fail (err == NULL || *err == NULL);

  const int buffer_length = 6;
  uint8_t *buffer = calloc (1, buffer_length);
  if (buffer == NULL)
    {
      g_set_error (err, MUMBLE_NETWORK_ERROR, MUMBLE_NETWORK_ERROR_FAIL,
                   "calloc failed");
      return;
    }

  *(uint16_t *) buffer = htons (packet_header->type);
  *(uint32_t *) (buffer + 2) = htonl (packet_header->length);

  GError *tmp_error = NULL;
  mumble_network_write_bytes (net, (const guint8 *) buffer, buffer_length,
                              &tmp_error);
  if (tmp_error != NULL)
    {
      g_propagate_error (err, tmp_error);
    }

  free (buffer);
}
