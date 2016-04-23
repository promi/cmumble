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

#ifndef __MBEDTLS_NETWORK_H__
#define __MBEDTLS_NETWORK_H__

#include <glib.h>
#include <glib-object.h>

#include "packet_header.h"
#include "network.h"

G_BEGIN_DECLS
#define MUMBLE_TYPE_MBEDTLS_NETWORK mumble_mbedtls_network_get_type ()
G_DECLARE_FINAL_TYPE (MumbleMbedtlsNetwork, mumble_mbedtls_network, MUMBLE,
                      MBEDTLS_NETWORK, MumbleNetwork)
     MumbleMbedtlsNetwork *mumble_mbedtls_network_new ();

     void mumble_mbedtls_network_connect (MumbleNetwork *net,
                                          const gchar *server_name,
                                          guint16 server_port,
                                          GError **err);

     void mumble_mbedtls_network_read_bytes (MumbleNetwork *net,
                                             guint8 *buffer,
                                             size_t buffer_length,
                                             GError **err);

     void mumble_mbedtls_network_write_bytes (MumbleNetwork *net,
                                              const guint8 *buffer,
                                              size_t buffer_length,
                                              GError **err);

G_END_DECLS
#endif // __NETWORK_H__
