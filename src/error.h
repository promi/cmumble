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

#ifndef __ERROR_H__
#define __ERROR_H__

#include <glib.h>

typedef enum _MumbleNetworkError
{
  MUMBLE_NETWORK_ERROR_ALLOCATION_FAIL,
  MUMBLE_NETWORK_ERROR_CONNECT_FAIL,
  MUMBLE_NETWORK_ERROR_FAIL
} MumbleNetworkError;

#define MUMBLE_NETWORK_ERROR mumble_network_error_quark ()

GQuark mumble_network_error_quark (void);

#endif // __ERROR_H__
