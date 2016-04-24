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

#include "Mumble.pb-c.h"

#include "error.h"
#include "packet_header.h"
#include "network.h"
#include "mbedtls_network.h"


#define APPLICATION_ID "com.github.promi.cmumble"

#define MUMBLE_PACKET_TYPE__VERSION 0
#define MUMBLE_PACKET_TYPE__AUTHENTICATE 2
#define MUMBLE_PACKET_TYPE__PING 3

#include "application.h"

typedef struct _MumbleApplication
{
  GApplication parent;

  GMainLoop *loop;
  GSettings *set;
  MumbleNetwork *net;

} MumbleApplication;

/* *INDENT-OFF* */
G_DEFINE_TYPE (MumbleApplication, mumble_application, G_TYPE_APPLICATION)
/* *INDENT-ON* */

void mumble_application_activate (GApplication *app);
void mumble_application_finalize (GObject *gobject);

static void
mumble_application_class_init (MumbleApplicationClass *klass)
{
  GObjectClass *g_object_class = G_OBJECT_CLASS (klass);
  g_object_class->finalize = mumble_application_finalize;

  GApplicationClass *application_class = G_APPLICATION_CLASS (klass);
  application_class->activate = mumble_application_activate;
}

static void
mumble_application_init (MumbleApplication *self)
{
  self->loop = g_main_loop_new (NULL, FALSE);
  g_return_if_fail (self->loop != NULL);
  self->set = g_settings_new (APPLICATION_ID);
  g_return_if_fail (self->set != NULL);
  self->net = MUMBLE_NETWORK (mumble_mbedtls_network_new ());
  g_return_if_fail (self->net != NULL);
}

void
mumble_application_finalize (GObject *gobject)
{
  g_return_if_fail (gobject != NULL);
  MumbleApplication *self = MUMBLE_APPLICATION (gobject);

  g_object_unref (self->net);
  g_object_unref (self->set);
  g_object_unref (self->loop);
  G_OBJECT_CLASS (mumble_application_parent_class)->finalize (gobject);
}

MumbleApplication *
mumble_application_new ()
{
  return g_object_new (MUMBLE_TYPE_APPLICATION, "application-id",
                       APPLICATION_ID, "flags",
                       G_APPLICATION_FLAGS_NONE, NULL);
}

void
send_our_version (MumbleNetwork *net, GError **err)
{
  g_return_if_fail (net != NULL);
  g_return_if_fail (err == NULL || *err == NULL);

  MumbleProto__Version version = MUMBLE_PROTO__VERSION__INIT;
  version.has_version = 1;
  version.version = 0x00010300;
  version.release = "Git version";
  version.os = "Unknown";
  version.os_version = "Unknown";
  mumble_network_write_packet (MUMBLE_PACKET_TYPE__VERSION, 
                               mumble_proto__version__get_packed_size, 
                               mumble_proto__version__pack, version,
                               tmp_err);

  MumblePacketHeader header = {
    MUMBLE_PACKET_TYPE__VERSION,
    mumble_proto__version__get_packed_size (&version)
  };

  GError *tmp_error = NULL;
  mumble_network_write_packet_header (net, &header, &tmp_error);
  if (tmp_error != NULL)
    {
      g_propagate_error (err, tmp_error);
      return;
    }

  guint8 *buffer = g_malloc0 (header.length);
  if (buffer == NULL)
    {
      g_set_error (err, MUMBLE_NETWORK_ERROR,
                   MUMBLE_NETWORK_ERROR_ALLOCATION_FAIL, "calloc failed");
      return;
    }

  mumble_proto__version__pack (&version, buffer);
  mumble_network_write_bytes (net, buffer, header.length, &tmp_error);
  if (tmp_error != NULL)
    {
      g_propagate_error (err, tmp_error);
    }
  g_free (buffer);
}

void
send_authenticate (MumbleNetwork *net, const gchar *username, GError **err)
{
  g_return_if_fail (net != NULL);
  g_return_if_fail (username != NULL);
  g_return_if_fail (err == NULL || *err == NULL);

  MumbleProto__Authenticate authenticate = MUMBLE_PROTO__AUTHENTICATE__INIT;
  authenticate.username = (gchar *) username;
  authenticate.password = "";
  authenticate.n_tokens = 0;
  authenticate.tokens = NULL;
  authenticate.n_celt_versions = 0;
  authenticate.celt_versions = NULL;
  authenticate.has_opus = 1;
  authenticate.opus = 1;

  MumblePacketHeader header = {
    MUMBLE_PACKET_TYPE__AUTHENTICATE,
    mumble_proto__authenticate__get_packed_size (&authenticate)
  };

  GError *tmp_error = NULL;
  mumble_network_write_packet_header (net, &header, &tmp_error);
  if (tmp_error != NULL)
    {
      g_propagate_error (err, tmp_error);
      return;
    }

  guint8 *buffer = g_malloc0 (header.length);
  if (buffer == NULL)
    {
      g_set_error (err, MUMBLE_NETWORK_ERROR,
                   MUMBLE_NETWORK_ERROR_ALLOCATION_FAIL, "calloc failed");
      return;
    }

  mumble_proto__authenticate__pack (&authenticate, buffer);

  mumble_network_write_bytes (net, buffer, header.length, &tmp_error);
  if (tmp_error != NULL)
    {
      g_propagate_error (err, tmp_error);
      g_free (buffer);
      return;
    }
  g_free (buffer);
}

void
send_ping (MumbleNetwork *net, GError **err)
{
  g_return_if_fail (net != NULL);
  g_return_if_fail (err == NULL || *err == NULL);

  MumbleProto__Ping ping = MUMBLE_PROTO__PING__INIT;
  ping.has_timestamp = 1;

  MumblePacketHeader header = {
    MUMBLE_PACKET_TYPE__PING,
    mumble_proto__ping__get_packed_size (&ping)
  };

  GError *tmp_error = NULL;
  mumble_network_write_packet_header (net, &header, &tmp_error);
  if (tmp_error != NULL)
    {
      g_propagate_error (err, tmp_error);
      return;
    }

  guint8 *buffer = g_malloc0 (header.length);
  if (buffer == NULL)
    {
      g_set_error (err, MUMBLE_NETWORK_ERROR,
                   MUMBLE_NETWORK_ERROR_ALLOCATION_FAIL, "calloc failed");
      return;
    }

  mumble_proto__ping__pack (&ping, buffer);

  mumble_network_write_bytes (net, buffer, header.length, &tmp_error);
  if (tmp_error != NULL)
    {
      g_propagate_error (err, tmp_error);
      g_free (buffer);
      return;
    }
  g_free (buffer);
}

void
receive_packet (MumbleNetwork *net, GError **err)
{
  MumblePacketHeader header;
  GError *tmp_error = NULL;
  mumble_network_read_packet_header (net, &header, &tmp_error);
  if (tmp_error != NULL)
    {
      g_propagate_error (err, tmp_error);
      return;
    }

  printf ("message type = %d\n", header.type);
  printf ("message length = %d\n", header.length);
  fflush (stdout);

  guint8 *buffer = g_malloc0 (header.length);
  if (buffer == NULL)
    {
      g_set_error (err, MUMBLE_NETWORK_ERROR,
                   MUMBLE_NETWORK_ERROR_ALLOCATION_FAIL, "calloc failed");
      return;
    }

  mumble_network_read_bytes (net, buffer, header.length, &tmp_error);
  if (tmp_error != NULL)
    {
      g_propagate_error (err, tmp_error);
      g_free (buffer);
      return;
    }

  if (header.type == MUMBLE_PACKET_TYPE__VERSION)
    {
      MumbleProto__Version *version =
        mumble_proto__version__unpack (NULL, header.length, buffer);

      printf ("version.has_version = %d\n", version->has_version);
      printf ("version.version = %x\n", version->version);
      printf ("version.release = %s\n", version->release);
      printf ("version.os = %s\n", version->os);
      printf ("version.os_version = %s\n", version->os_version);
      mumble_proto__version__free_unpacked (version, NULL);
    }

  g_free (buffer);
}

gboolean
mumble_timeout (gpointer user_data)
{
  printf ("PING\n");
  MumbleNetwork *net = MUMBLE_NETWORK (user_data);
  GError *err = NULL;
  send_ping (net, &err);
  if (err != NULL)
    {
      fprintf (stderr,
               "could not send PING packet to the server: %s\n",
               err->message);
      return FALSE;
    }
  return TRUE;
}

gboolean
mumble_timeout2 (gpointer user_data)
{
  MumbleNetwork *net = MUMBLE_NETWORK (user_data);
  GError *err = NULL;
  receive_packet (net, &err);
  if (err != NULL)
    {
      fprintf (stderr,
               "could not receive packet to the server: %s\n", err->message);
      return FALSE;
    }
  return TRUE;
}

void
mumble_application_activate (GApplication *app)
{
  printf ("Activate\n");
  MumbleApplication *self = MUMBLE_APPLICATION (app);

  gchar *server_name = g_settings_get_string (self->set, "server-name");
  guint16 server_port = g_settings_get_int (self->set, "server-port");
  gchar *user_name = g_settings_get_string (self->set, "user-name");

  GError *err = NULL;
  mumble_network_connect (self->net, server_name, server_port, &err);
  if (err != NULL)
    {
      fprintf (stderr, "could not connect to the server: %s\n", err->message);
      goto fail_cleanup;
    }

  send_our_version (self->net, &err);
  if (err != NULL)
    {
      fprintf (stderr, "could not send our version to the server: %s\n",
               err->message);
      goto fail_cleanup;
    }

  send_authenticate (self->net, user_name, &err);
  if (err != NULL)
    {
      fprintf (stderr, "could not send authenticate to the server: %s\n",
               err->message);
      goto fail_cleanup;
    }

  g_timeout_add_seconds (20, mumble_timeout, self->net);
  g_timeout_add (1, mumble_timeout2, self->net);
  g_application_hold (app);
  goto finally;

fail_cleanup:
  g_error_free (err);

finally:
  g_free (user_name);
  g_free (server_name);
}
