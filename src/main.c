/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 4; tab-width: 4 -*-  */
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

#include "utils.h"
#include "packet_header.h"
#include "network.h"

#define SERVER_PORT "10012"
#define SERVER_NAME "voice.mumbletreff.de"

#define MUMBLE_PACKET_TYPE__VERSION 0
#define MUMBLE_PACKET_TYPE__AUTHENTICATE 2

int main(void)
{
	cmumble_network *net = cmumble_network_init();
	cmumble_network_connect(net, SERVER_NAME, SERVER_PORT);

	{
		MumbleProto__Version version = MUMBLE_PROTO__VERSION__INIT;
		version.has_version = 1;
		version.version = 0x00010300;
		version.release = "Git version";
		version.os = "Unknown";
		version.os_version = "Unknown";

		cmumble_packet_header header = {
			MUMBLE_PACKET_TYPE__VERSION,
			mumble_proto__version__get_packed_size (&version)
		};
		cmumble_network_write_packet_header (net, &header);
		uint8_t *buffer = calloc(1, header.length);
		if (buffer == NULL)
		{
			exit_with_message(23, "calloc failed");
		}
		mumble_proto__version__pack(&version, buffer);
		cmumble_network_write_bytes(net, buffer, header.length);
		free(buffer);
	}

	{
		MumbleProto__Authenticate authenticate =
			MUMBLE_PROTO__AUTHENTICATE__INIT;
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
		uint8_t *buffer = calloc(1, header.length);
		if (buffer == NULL)
		{
			exit_with_message(24, "calloc failed");
		}
		mumble_proto__authenticate__pack(&authenticate, buffer);
		cmumble_network_write_bytes(net, buffer, header.length);
		free(buffer);
	}

	while(1)
	{
		cmumble_packet_header header = cmumble_network_read_packet_header(net);
		printf ("message type = %d\n", header.type);
		printf ("message length = %d\n", header.length);
		fflush(stdout);
		uint8_t *buffer = calloc(1, header.length);
		if (buffer == NULL)
		{
			exit_with_message(25, "calloc failed");
		}
		cmumble_network_read_bytes(net, buffer, header.length);
		if (header.type == MUMBLE_PACKET_TYPE__VERSION)
		{
			MumbleProto__Version *version =
				mumble_proto__version__unpack(NULL, header.length, buffer);

			printf("version.has_version = %d\n", version->has_version);
			printf("version.version = %x\n", version->version);
			printf("version.release = %s\n", version->release);
			printf("version.os = %s\n", version->os);
			printf("version.os_version = %s\n", version->os_version);
			mumble_proto__version__free_unpacked(version, NULL);
		}
		free(buffer);
	}
	cmumble_network_free(net);
	return 0;
}
