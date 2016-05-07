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
#include <inttypes.h>

#include <opus/opus.h>
#include <ogg/ogg.h>
#include <vorbis/vorbisenc.h>
#include <shout/shout.h>

#include "Mumble.pb-c.h"

#include "error.h"
#include "packet_header.h"
#include "network.h"

#define APPLICATION_ID "com.github.promi.cmumble"

#include "application.h"

const int channels = 2;

typedef struct _MumbleApplication
{
  GApplication parent;

  GMainLoop *loop;
  GSettings *set;
  MumbleNetwork *net;
  GHashTable *session_opus_decoders;
  GHashTable *session_pcm_sample_queues;

  vorbis_info vorbis_info;
  vorbis_dsp_state vorbis_dsp_state;
  vorbis_block vorbis_block;
  ogg_stream_state ogg_stream_state;
  vorbis_comment vorbis_comment;

  shout_t *shout;

  GMutex mutex;

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

void
free_pcm_sample_queue (gpointer data)
{
  g_queue_free_full (data, g_free);
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
  self->session_opus_decoders =
    g_hash_table_new_full (g_direct_hash, g_direct_equal, NULL,
                           (GDestroyNotify) opus_decoder_destroy);
  g_return_if_fail (self->session_opus_decoders != NULL);
  self->session_pcm_sample_queues =
    g_hash_table_new_full (g_direct_hash, g_direct_equal, NULL,
                           free_pcm_sample_queue);
  g_return_if_fail (self->session_pcm_sample_queues != NULL);
  shout_init ();
  self->shout = shout_new ();
  g_return_if_fail (self->shout != NULL);

  int r = shout_set_host (self->shout, "example.com");
  g_return_if_fail (r == SHOUTERR_SUCCESS);

  r = shout_set_protocol (self->shout, SHOUT_PROTOCOL_HTTP);
  g_return_if_fail (r == SHOUTERR_SUCCESS);

  r = shout_set_port (self->shout, 8000);
  g_return_if_fail (r == SHOUTERR_SUCCESS);

  r = shout_set_password (self->shout, "hackme");
  g_return_if_fail (r == SHOUTERR_SUCCESS);

  r = shout_set_mount (self->shout, "/test.ogg");
  g_return_if_fail (r == SHOUTERR_SUCCESS);

  r = shout_set_user (self->shout, "source");
  g_return_if_fail (r == SHOUTERR_SUCCESS);

  shout_set_format (self->shout, SHOUT_FORMAT_OGG);
  g_return_if_fail (r == SHOUTERR_SUCCESS);

  r = shout_open (self->shout);
  printf ("%d %s\n", r, shout_get_error (self->shout));
  g_return_if_fail (r == SHOUTERR_SUCCESS);

  vorbis_info_init (&self->vorbis_info);
  vorbis_encode_init_vbr (&self->vorbis_info, channels, 48000, 0.0);
  r = vorbis_analysis_init (&self->vorbis_dsp_state, &self->vorbis_info);
  printf ("%d\n", r);
  g_return_if_fail (r == 0);
  r = vorbis_block_init (&self->vorbis_dsp_state, &self->vorbis_block);
  g_return_if_fail (r == 0);
  r = ogg_stream_init (&self->ogg_stream_state, 0);
  g_return_if_fail (r == 0);
  vorbis_comment_init (&self->vorbis_comment);

  ogg_packet header_packet;
  ogg_packet comment_header_packet;
  ogg_packet code_header_packet;

  r = vorbis_analysis_headerout (&self->vorbis_dsp_state,
                                 &self->vorbis_comment,
                                 &header_packet,
                                 &comment_header_packet, &code_header_packet);
  g_return_if_fail (r == 0);

  r = ogg_stream_packetin (&self->ogg_stream_state, &header_packet);
  g_return_if_fail (r == 0);
  r = ogg_stream_packetin (&self->ogg_stream_state, &comment_header_packet);
  g_return_if_fail (r == 0);
  r = ogg_stream_packetin (&self->ogg_stream_state, &code_header_packet);
  g_return_if_fail (r == 0);

  ogg_page ogg_page;
  while (ogg_stream_flush (&self->ogg_stream_state, &ogg_page))
    {
      r = shout_send (self->shout, ogg_page.header, ogg_page.header_len);
      g_return_if_fail (r == 0);
      r = shout_send (self->shout, ogg_page.body, ogg_page.body_len);
      g_return_if_fail (r == 0);
    }

  vorbis_comment_clear (&self->vorbis_comment);

  g_mutex_init (&self->mutex);
}

void
mumble_application_finalize (GObject *gobject)
{
  g_return_if_fail (gobject != NULL);
  MumbleApplication *self = MUMBLE_APPLICATION (gobject);

  vorbis_comment_clear (&self->vorbis_comment);
  ogg_stream_clear (&self->ogg_stream_state);
  vorbis_block_clear (&self->vorbis_block);
  vorbis_dsp_clear (&self->vorbis_dsp_state);
  vorbis_info_clear (&self->vorbis_info);
  shout_close (self->shout);
  shout_shutdown ();
  g_object_unref (self->session_pcm_sample_queues);
  g_object_unref (self->session_opus_decoders);
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

  MUMBLE_NETWORK_WRITE_PACKET (net, VERSION, version, &message, err);
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

  MUMBLE_NETWORK_WRITE_PACKET (net, AUTHENTICATE, authenticate, &message,
                               err);
}

void
send_ping (MumbleNetwork *net, GError **err)
{
  g_return_if_fail (net != NULL);
  g_return_if_fail (err == NULL || *err == NULL);

  MumbleProto__Ping message = MUMBLE_PROTO__PING__INIT;
  // message.has_timestamp = 1;

  MUMBLE_NETWORK_WRITE_PACKET (net, PING, ping, &message, err);
}

OpusDecoder *
get_decoder (MumbleApplication *self, guint32 session_id, gint channels)
{
  OpusDecoder *decoder;
  if (g_hash_table_lookup_extended
      (self->session_opus_decoders, GINT_TO_POINTER (session_id),
       NULL, (gpointer) & decoder) == FALSE)
    {
      int oerr = 0;
      decoder = opus_decoder_create (48000, channels, &oerr);
      g_return_val_if_fail (oerr == OPUS_OK, NULL);
      g_hash_table_insert (self->session_opus_decoders,
                           GINT_TO_POINTER (session_id), decoder);
    }
  return decoder;
}

gsize
get_pcm_frames_length (gint32 Fs, gint channels)
{
  // 120 ms is the maximum PCM frame length the opus decoder can write at once
  return Fs / 1000 * 120 * channels;
}

void
write_pcm_samples_to_shout (MumbleApplication *self, gfloat *samples,
                            gsize samples_length)
{
  gfloat **buffer = vorbis_analysis_buffer (&self->vorbis_dsp_state,
                                            samples_length / channels);
  // Interleaved -> non interleaved
  for (gsize i = 0; i < samples_length; i++)
    {
      buffer[i % channels][i / channels] = samples[i];
    }
  int r = vorbis_analysis_wrote (&self->vorbis_dsp_state,
                                 samples_length / channels);
  g_return_if_fail (r == 0);
  while (vorbis_analysis_blockout
         (&self->vorbis_dsp_state, &self->vorbis_block) == 1)
    {
      ogg_packet ogg_packet;
      ogg_page ogg_page;

      vorbis_analysis (&self->vorbis_block, &ogg_packet);
      vorbis_bitrate_addblock (&self->vorbis_block);

      while (vorbis_bitrate_flushpacket
             (&self->vorbis_dsp_state, &ogg_packet))
        {
          ogg_stream_packetin (&self->ogg_stream_state, &ogg_packet);

          while (ogg_stream_pageout (&self->ogg_stream_state, &ogg_page))
            {
              r =
                shout_send (self->shout, ogg_page.header,
                            ogg_page.header_len);
              g_return_if_fail (r == SHOUTERR_SUCCESS);
              r = shout_send (self->shout, ogg_page.body, ogg_page.body_len);
              g_return_if_fail (r == SHOUTERR_SUCCESS);
            }
        }
    }
}

gpointer
shout_thread (gpointer data)
{
  MumbleApplication *self = MUMBLE_APPLICATION (data);
  while (1)
    {
      g_mutex_lock (&self->mutex);
      GArray *arr = g_array_new (FALSE, FALSE, sizeof (gfloat));
      g_array_set_size (arr, 480);
          for (int i = 0; i <= 480; i++)
            {
                  ((gfloat *) arr->data)[i] = 0;
            }
      guint32 session_id;
      GQueue *queue;
      GHashTableIter iter;
      g_hash_table_iter_init (&iter, self->session_pcm_sample_queues);
      while (g_hash_table_iter_next (&iter, (gpointer *) & session_id,
                                     (gpointer *) & queue))
        {
          for (int i = 0; i <= 480; i++)
            {
              gfloat *sample = g_queue_pop_head (queue);
              if (sample)
                {
                  ((gfloat *) arr->data)[i] =
                    ((gfloat *) arr->data)[i] + *sample;
                }
            }
        }
      write_pcm_samples_to_shout (self, (gfloat *) arr->data, arr->len);
      g_array_unref (arr);
      g_mutex_unlock (&self->mutex);
      g_usleep(5000);
    }
  return NULL;
}

void
enqueue_pcm_samples (MumbleApplication *self, guint32 session_id,
                     gfloat *samples, gsize samples_length)
{
  g_mutex_lock (&self->mutex);
  GQueue *queue;
  if (g_hash_table_lookup_extended
      (self->session_pcm_sample_queues, GINT_TO_POINTER (session_id),
       NULL, (gpointer) & queue) == FALSE)
    {
      queue = g_queue_new ();
      g_hash_table_insert (self->session_pcm_sample_queues,
                           GINT_TO_POINTER (session_id), queue);
    }
  g_return_if_fail (queue != NULL);

  for (gsize i = 0; i < samples_length; i++)
    {
      gfloat *sample = g_malloc0 (sizeof (samples[i]));
      *sample = samples[i];
      g_queue_push_tail (queue, sample);
    }
  g_mutex_unlock (&self->mutex);
}

void
read_opus_data (MumbleApplication *self, guint8 *data, gsize data_length,
                guint read_index, guint32 session_id)
{
  g_return_if_fail (self != NULL);
  g_return_if_fail (data != NULL);
  g_return_if_fail (data_length > 0);
  g_return_if_fail (channels == 1 || channels == 2);
  OpusDecoder *decoder = get_decoder (self, session_id, channels);
  g_return_if_fail (decoder != NULL);

  guint16 opus_header =
    (guint16) packet_data_stream_decode (data, &read_index);
  guint16 opus_length = opus_header & 0x1FFF;
  g_return_if_fail (read_index + opus_length <= data_length);
  const gsize pcm_frames_length = get_pcm_frames_length (48000, channels);
  gfloat *pcm_frames = g_malloc0 (sizeof (gfloat) * pcm_frames_length);
  const int err = opus_decode_float (decoder, data + read_index, opus_length,
                                     pcm_frames, pcm_frames_length, 0);
  g_return_if_fail (err >= 0);
  printf ("OPUS Decoded %d samples from %" G_GSIZE_FORMAT " bytes\n", err,
          data_length);
  enqueue_pcm_samples (self, session_id, pcm_frames, (gsize) err * channels);
  g_free (pcm_frames);
  if ((opus_header & 0x2000) != 0)
    {
      opus_decoder_ctl (decoder, OPUS_RESET_STATE);
    }
}

void
read_audio_data (MumbleApplication *self, guint8 *data, guint32 data_length)
{
  guint8 header = data[0];
  // Upper three bits
  guint8 type = (header & 0xE0) >> 5;
  // Lower five bits
  guint8 target = header & 0x1F;
  if (type == 1)
    {
      // Target is always zero in ping message
      g_return_if_fail (target == 0);
      g_return_if_fail (header == 0x20);
      // TODO: Process ping message
    }
  else
    {
      // TODO: Make sure varint decoding doesn't read outside buffer data range
      guint read_index = 1;
      guint32 session_id =
        (guint32) packet_data_stream_decode (data, &read_index);
      printf ("SID = %d, ", session_id);
      guint64 sequence_number = packet_data_stream_decode (data, &read_index);
      printf ("SEQ = %" G_GUINT64_FORMAT ", ", sequence_number);
      if (type == 4)
        {
          // Opus data
          read_opus_data (self, data, data_length, read_index, session_id);
        }
    }
}

gboolean
read_message (MumbleNetwork *net, MumbleMessageType type, guint8 *data,
              guint32 length, gpointer user_data)
{
  g_return_val_if_fail (net != NULL, FALSE);
  g_return_val_if_fail (user_data != NULL, FALSE);
  MumbleApplication *self = MUMBLE_APPLICATION (user_data);
  // Payload could be empty (i.e. PING message without any actual data filled)
  // That's not an error
  if (data == NULL)
    {
      return TRUE;
    }
  g_return_val_if_fail (length != 0, FALSE);

  if (type == MUMBLE_MESSAGE_TYPE__VERSION)
    {
      MumbleProto__Version *message =
        mumble_proto__version__unpack (NULL, length, data);
      printf ("\nreceived version message\n");
      if (message->has_version == 1)
        {
          printf ("version = %x\n", message->version);
        }
      printf ("release = %s\n", message->release);
      printf ("os = %s\n", message->os);
      printf ("os_version = %s\n", message->os_version);
      printf ("\n");
      mumble_proto__version__free_unpacked (message, NULL);
    }
  else if (type == MUMBLE_MESSAGE_TYPE__UDP_TUNNEL)
    {
      read_audio_data (self, data, length);
    }
  else if (type == MUMBLE_MESSAGE_TYPE__REJECT)
    {
      MumbleProto__Reject *message =
        mumble_proto__reject__unpack (NULL, length, data);
      printf ("\nreceived reject message\n");
      if (message->has_type == 1)
        {
          printf ("type = %d\n", message->type);
        }
      printf ("reason = %s\n", message->reason);
      printf ("\n");
      mumble_proto__reject__free_unpacked (message, NULL);
      g_free (data);
      return FALSE;
    }
  else
    {
      printf ("%d[%d] ", type, length);
    }

  g_free (data);
  return TRUE;
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

  mumble_network_read_packet_async (self->net, &read_message, self, &err);
  if (err != NULL)
    {
      fprintf (stderr,
               "Could not start reading from server : '%s'\n", err->message);
      goto fail_cleanup;
    }

  g_timeout_add_seconds (20, mumble_timeout, self->net);
  g_thread_new ("shout", shout_thread, self);
  g_application_hold (app);
  goto finally;

fail_cleanup:
  g_error_free (err);

finally:
  g_free (user_name);
  g_free (server_name);
}
