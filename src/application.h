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

#ifndef __APPLICATION_H__
#define __APPLICATION_H__

#include <glib.h>
#include <glib-object.h>
#include <gio/gio.h>

/* *INDENT-OFF* */
G_BEGIN_DECLS
#define MUMBLE_TYPE_APPLICATION mumble_application_get_type ()
G_DECLARE_FINAL_TYPE (MumbleApplication, mumble_application, MUMBLE,
                      APPLICATION, GApplication)
/* *INDENT-ON* */
MumbleApplication *mumble_application_new ();

/* *INDENT-OFF* */
G_END_DECLS
/* *INDENT-ON* */

#endif // __NETWORK_H__
