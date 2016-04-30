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

#include "packet_data_stream.h"

guint64
packet_data_stream_decode (guint8 *buffer, gint *read_index)
{
  guint64 v0 = (guint64) buffer[(*read_index)++];
  if ((v0 & 0x80) == 0x00)
    {
      return v0 & 0x7F;
    }
  else if ((v0 & 0xC0) == 0x80)
    {
      guint64 v1 = (guint64) buffer[(*read_index)++];
      return (v0 & 0x4F) << 8 | v1;
    }
  else if ((v0 & 0xF0) == 0xF0)
    {
      if ((v0 & 0xFC) == 0xF0)
        {
          guint64 v1 = (guint64) buffer[(*read_index)++];
          guint64 v2 = (guint64) buffer[(*read_index)++];
          guint64 v3 = (guint64) buffer[(*read_index)++];
          guint64 v4 = (guint64) buffer[(*read_index)++];
          return v1 << 24 | v2 << 16 | v3 << 8 | v4;
        }
      else if ((v0 & 0xFC) == 0xF4)
        {
          guint64 v1 = (guint64) buffer[(*read_index)++];
          guint64 v2 = (guint64) buffer[(*read_index)++];
          guint64 v3 = (guint64) buffer[(*read_index)++];
          guint64 v4 = (guint64) buffer[(*read_index)++];
          guint64 v5 = (guint64) buffer[(*read_index)++];
          guint64 v6 = (guint64) buffer[(*read_index)++];
          guint64 v7 = (guint64) buffer[(*read_index)++];
          guint64 v8 = (guint64) buffer[(*read_index)++];
          return v1 << 56 | v2 << 48 | v3 << 40 | v4 << 32 |
            v5 << 24 | v6 << 16 | v7 << 8 | v8;
        }
      else if ((v0 & 0xFC) == 0xF8)
        {
          return (-1) * packet_data_stream_decode (buffer, read_index);
        }
      else if ((v0 & 0xFC) == 0xFC)
        {
          return (-1) * (v0 & 0x03);
        }
      else
        {
          g_return_val_if_reached (0);
        }
    }
  else if ((v0 & 0xF0) == 0xE0)
    {
      guint64 v1 = (guint64) buffer[(*read_index)++];
      guint64 v2 = (guint64) buffer[(*read_index)++];
      guint64 v3 = (guint64) buffer[(*read_index)++];
      return (v0 & 0x0F) << 24 | v1 << 16 | v2 << 8 | v3;
    }
  else if ((v0 & 0xE0) == 0xC0)
    {
      guint64 v1 = (guint64) buffer[(*read_index)++];
      guint64 v2 = (guint64) buffer[(*read_index)++];
      return (v0 & 0x1F) << 16 | v1 << 8 | v2;
    }
  else
    {
      g_return_val_if_reached (0);
    }
}
