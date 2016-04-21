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
#include <stdlib.h>

#include "Mumble.pb-c.h"

#include "error.h"
#include "utils.h"
#include "packet_header.h"
#include "network.h"

#define SERVER_PORT "10012"
#define SERVER_NAME "voice.mumbletreff.de"

#define MUMBLE_PACKET_TYPE__VERSION 0
#define MUMBLE_PACKET_TYPE__AUTHENTICATE 2

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

  uint8_t *buffer = calloc (1, header.length);
  if (buffer == NULL)
    {
      g_set_error (err, MUMBLE_NETWORK_ERROR,
                   MUMBLE_NETWORK_ERROR_ALLOCATION_FAIL,
                   "Could not allocate buffer for version packet");
      return;
    }

  mumble_proto__version__pack (&version, buffer);
  mumble_network_write_bytes (net, buffer, header.length, &tmp_error);
  if (tmp_error != NULL)
    {
      g_propagate_error (err, tmp_error);
    }
  free (buffer);
}

int
main (void)
{
  MumbleNetwork *net = mumble_network_new ();
  if (net == NULL)
    {
      fprintf (stderr, "could not allocate MumbleNetwork class\n");
      return 1;
    }

  GError *err = NULL;
  mumble_network_connect (net, SERVER_NAME, SERVER_PORT, &err);
  if (err != NULL)
    {
      fprintf (stderr, "could not connect to the server: %s\n", err->message);
      g_error_free (err);
      g_object_unref (net);
      return 1;
    }

  /*
     {
     MumbleProto__Authenticate authenticate = MUMBLE_PROTO__AUTHENTICATE__INIT;
     authenticate.username = "Testclient1";
     authenticate.password = "";
     authenticate.n_tokens = 0;
     authenticate.tokens = NULL;
     authenticate.n_celt_versions = 0;
     authenticate.celt_versions = NULL;
     authenticate.has_opus = 1;
     authenticate.opus = 1;

     cmumble_packet_header header = {
     MUMBLE_PACKET_TYPE__AUTHENTICATE,
     mumble_proto__authenticate__get_packed_size (&authenticate)
     };
     cmumble_network_write_packet_header (net, &header);
     uint8_t *buffer = calloc (1, header.length);
     if (buffer == NULL)
     {
     exit_with_message (24, "calloc failed");
     }
     mumble_proto__authenticate__pack (&authenticate, buffer);
     cmumble_network_write_bytes (net, buffer, header.length);
     free (buffer);
     }

     // Main loop
     // TODO: Send ping package, so that the server doesn't kick us ;)
     // Also probably better use select() instead of polling with read()
     while (1)
     {
     cmumble_packet_header header;
     cmumble_network_read_packet_header (net, &header);
     printf ("message type = %d\n", header.type);
     printf ("message length = %d\n", header.length);
     fflush (stdout);
     uint8_t *buffer = calloc (1, header.length);
     if (buffer == NULL)
     {
     exit_with_message (25, "calloc failed");
     }
     cmumble_network_read_bytes (net, buffer, header.length);
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
     free (buffer);
     }

     ret = 0;
     fail_network_connect:
     cmumble_network_free (net);
     fail_network_init:
     return ret;
   */
  g_object_unref (net);
  return 0;
}
