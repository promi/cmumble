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

#define APPLICATION_ID "com.github.promi.cmumble"

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
  self->net = mumble_network_new ();
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

  MumbleProto__Version message = MUMBLE_PROTO__VERSION__INIT;
  message.has_version = 1;
  message.version = 0x00010300;
  message.release = "cmumble (git)";
  message.os = "Unknown";
  message.os_version = "Unknown";

  mumble_network_write_packet (net, MUMBLE_PACKET_TYPE__VERSION,
                               (mumble_message_get_packed_size)
                               mumble_proto__version__get_packed_size,
                               (mumble_message_pack)
                               mumble_proto__version__pack, &message, err);
}

void
send_authenticate (MumbleNetwork *net, const gchar *username, GError **err)
{
  g_return_if_fail (net != NULL);
  g_return_if_fail (username != NULL);
  g_return_if_fail (err == NULL || *err == NULL);

  MumbleProto__Authenticate message = MUMBLE_PROTO__AUTHENTICATE__INIT;
  message.username = (gchar *) username;
  message.password = "";
  message.n_tokens = 0;
  message.tokens = NULL;
  message.n_celt_versions = 0;
  message.celt_versions = NULL;
  message.has_opus = 1;
  message.opus = 1;

  mumble_network_write_packet (net, MUMBLE_PACKET_TYPE__AUTHENTICATE,
                               (mumble_message_get_packed_size)
                               mumble_proto__authenticate__get_packed_size,
                               (mumble_message_pack)
                               mumble_proto__authenticate__pack, &message,
                               err);
}

void
send_ping (MumbleNetwork *net, GError **err)
{
  g_return_if_fail (net != NULL);
  g_return_if_fail (err == NULL || *err == NULL);

  MumbleProto__Ping message = MUMBLE_PROTO__PING__INIT;
  // message.has_timestamp = 1;

  mumble_network_write_packet (net, MUMBLE_PACKET_TYPE__PING,
                               (mumble_message_get_packed_size)
                               mumble_proto__ping__get_packed_size,
                               (mumble_message_pack)
                               mumble_proto__ping__pack, &message, err);
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

  // printf ("%d[%d] ", header.type, header.length);
  // fflush (stdout);

  // Payload could be empty (i.e. PING message without any actual data filled)
  // That's not an error, only just don't try to receive any payload in that
  // case
  if (header.length > 0)
    {
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
               "could not receive packet from the server: %s\n",
               err->message);
      return FALSE;
    }
  return TRUE;
}

void
mumble_application_activate (GApplication *app)
{
  MumbleApplication *self = MUMBLE_APPLICATION (app);

  gchar *server_name = g_settings_get_string (self->set, "server-name");
  guint16 server_port = g_settings_get_int (self->set, "server-port");
  gchar *user_name = g_settings_get_string (self->set, "user-name");

  gchar *cert_filename = g_strconcat (g_get_user_config_dir (),
                                      "/cmumble/cmumble.pem", NULL);
  GError *err = NULL;
  GTlsCertificate *certificate =
    g_tls_certificate_new_from_file (cert_filename,
                                     &err);
  if (err != NULL)
    {
      g_return_if_fail (certificate == NULL);
      fprintf (stderr, "Certificate load error: '%s'\n", err->message);
      g_clear_error (&err);
    }
  g_free (cert_filename);

  mumble_network_connect (self->net, server_name, server_port, certificate,
                          &err);
  if (err != NULL)
    {
      fprintf (stderr, "Could not connect to the server '%s:%d': '%s'\n",
               server_name, server_port, err->message);
      goto fail_cleanup;
    }

  send_our_version (self->net, &err);
  if (err != NULL)
    {
      fprintf (stderr, "Could not send our version to the server: '%s'\n",
               err->message);
      goto fail_cleanup;
    }

  send_authenticate (self->net, user_name, &err);
  if (err != NULL)
    {
      fprintf (stderr,
               "Could not send authenticate to the server : '%s'\n",
               err->message);
      goto fail_cleanup;
    }

  mumble_network_read_packet_async (self->net, &err);
  if (err != NULL)
    {
      fprintf (stderr,
               "Could not start reading from server : '%s'\n", err->message);
      goto fail_cleanup;
    }

  g_timeout_add_seconds (20, mumble_timeout, self->net);
  g_application_hold (app);
  goto finally;

fail_cleanup:
  g_error_free (err);

finally:
  g_free (user_name);
  g_free (server_name);
}
