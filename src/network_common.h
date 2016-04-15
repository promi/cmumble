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

#pragma once

cmumble_network* cmumble_network_init ();
void cmumble_network_connect (cmumble_network *net, const char *server_name,
                              const char *server_port);
void cmumble_network_read_bytes(cmumble_network *net, uint8_t *buffer,
                                 size_t buffer_length);
cmumble_packet_header cmumble_network_read_packet_header (cmumble_network *net);
void cmumble_network_write_bytes(cmumble_network *net, const uint8_t *buffer,
                                 size_t buffer_length);
void cmumble_network_write_packet_header (cmumble_network *net, 
                                   const cmumble_packet_header *header);
void cmumble_network_free(cmumble_network *net);
