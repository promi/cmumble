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

#include <arpa/inet.h>
#include <string.h>
#include <mbedtls/net.h>
#include <mbedtls/ssl.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/debug.h>

#include "error.h"
#include "mbedtls_network.h"

typedef struct _MumbleMbedtlsNetwork
{
  MumbleNetwork parent;

  mbedtls_net_context server_fd;
  mbedtls_entropy_context entropy;
  mbedtls_ctr_drbg_context ctr_drbg;
  mbedtls_ssl_context ssl;
  mbedtls_ssl_config conf;
  mbedtls_x509_crt cacert;
} MumbleMbedtlsNetwork;

/* *INDENT-OFF* */
G_DEFINE_TYPE (MumbleMbedtlsNetwork, mumble_mbedtls_network,
               MUMBLE_TYPE_NETWORK)
/* *INDENT-ON* */

static const char pers[] = "cmumble";

static void mumble_mbedtls_network_finalize (GObject *object);

static void
mumble_mbedtls_network_class_init (MumbleMbedtlsNetworkClass *klass)
{
  GObjectClass *gobject_class = G_OBJECT_CLASS (klass);
  gobject_class->finalize = mumble_mbedtls_network_finalize;

  MumbleNetworkClass *mumble_network_class = MUMBLE_NETWORK_CLASS (klass);
  mumble_network_class->connect = mumble_mbedtls_network_connect;
  mumble_network_class->read_bytes = mumble_mbedtls_network_read_bytes;
  mumble_network_class->write_bytes = mumble_mbedtls_network_write_bytes;
}

static void
mumble_mbedtls_network_init (MumbleMbedtlsNetwork *net)
{
  mbedtls_net_init (&net->server_fd);
  mbedtls_ssl_init (&net->ssl);
  mbedtls_ssl_config_init (&net->conf);
  mbedtls_x509_crt_init (&net->cacert);
  mbedtls_ctr_drbg_init (&net->ctr_drbg);
  mbedtls_entropy_init (&net->entropy);
}

static void
mumble_mbedtls_network_finalize (GObject *object)
{
  MumbleMbedtlsNetwork *net = MUMBLE_MBEDTLS_NETWORK (object);
  mbedtls_net_free (&net->server_fd);
  mbedtls_ssl_free (&net->ssl);
  mbedtls_ssl_config_free (&net->conf);
  mbedtls_ctr_drbg_free (&net->ctr_drbg);
  mbedtls_entropy_free (&net->entropy);

  GObjectClass *parent_class =
    G_OBJECT_CLASS (mumble_mbedtls_network_parent_class);
  (*parent_class->finalize) (object);
}

MumbleMbedtlsNetwork *
mumble_mbedtls_network_new (void)
{
  return g_object_new (MUMBLE_TYPE_MBEDTLS_NETWORK, NULL);
}

static void
my_debug (void *ctx, int level, const char *file, int line, const char *str)
{
  ((void) level);
  fprintf ((FILE *) ctx, "%s:%04d: %s", file, line, str);
  fflush ((FILE *) ctx);
}

void
mumble_mbedtls_network_connect (MumbleNetwork *self,
                                const gchar *server_name,
                                guint16 server_port, GError **err)
{
  g_return_if_fail (self != NULL);
  g_return_if_fail (server_name != NULL);
  g_return_if_fail (err == NULL || *err == NULL);
  MumbleMbedtlsNetwork *net = MUMBLE_MBEDTLS_NETWORK (self);

  int ret;
  if ((ret = mbedtls_ctr_drbg_seed (&net->ctr_drbg, mbedtls_entropy_func,
                                    &net->entropy, (const uint8_t *) pers,
                                    strlen (pers))) != 0)
    {
      g_set_error (err, MUMBLE_NETWORK_ERROR, MUMBLE_NETWORK_ERROR_FAIL,
                   "mbedtls_ctr_drbg_seed returned %d (-0x%04x)", ret, -ret);
      return;
    }

  gchar *server_port_s = g_strdup_printf ("%d", server_port);
  if ((ret = mbedtls_net_connect (&net->server_fd, server_name, server_port_s,
                                  MBEDTLS_NET_PROTO_TCP)) != 0)
    {
      g_set_error (err, MUMBLE_NETWORK_ERROR, MUMBLE_NETWORK_ERROR_FAIL,
                   "mbedtls_net_connect returned %d (-0x%04x)", ret, -ret);
      g_free (server_port_s);
      return;
    }
  g_free (server_port_s);

  if ((ret = mbedtls_ssl_config_defaults (&net->conf, MBEDTLS_SSL_IS_CLIENT,
                                          MBEDTLS_SSL_TRANSPORT_STREAM,
                                          MBEDTLS_SSL_PRESET_DEFAULT)) != 0)
    {
      g_set_error (err, MUMBLE_NETWORK_ERROR, MUMBLE_NETWORK_ERROR_FAIL,
                   "mbedtls_ssl_config_defaults returned %d (-0x%04x)", ret,
                   -ret);
      return;
    }

  mbedtls_ssl_conf_authmode (&net->conf, MBEDTLS_SSL_VERIFY_NONE);

  mbedtls_ssl_conf_rng (&net->conf, mbedtls_ctr_drbg_random, &net->ctr_drbg);
  mbedtls_ssl_conf_dbg (&net->conf, my_debug, stdout);

  if ((ret = mbedtls_ssl_setup (&net->ssl, &net->conf)) != 0)
    {
      g_set_error (err, MUMBLE_NETWORK_ERROR, MUMBLE_NETWORK_ERROR_FAIL,
                   "mbedtls_ssl_setup returned %d (-0x%04x)", ret, -ret);
      return;
    }

  mbedtls_ssl_set_bio (&net->ssl, &net->server_fd, mbedtls_net_send,
                       mbedtls_net_recv, NULL);

  while ((ret = mbedtls_ssl_handshake (&net->ssl)) != 0)
    {
      if (ret != MBEDTLS_ERR_SSL_WANT_READ &&
          ret != MBEDTLS_ERR_SSL_WANT_WRITE)
        {
          g_set_error (err, MUMBLE_NETWORK_ERROR, MUMBLE_NETWORK_ERROR_FAIL,
                       "mbedtls_ssl_handshake returned %d (-0x%04x)", ret,
                       -ret);
          return;
        }
    }
}

void
mumble_mbedtls_network_read_bytes (MumbleNetwork *self, guint8 *buffer,
                                   size_t length, GError **err)
{
  g_return_if_fail (self != NULL);
  g_return_if_fail (buffer != NULL);
  g_return_if_fail (length > 0);
  g_return_if_fail (err == NULL || *err == NULL);
  MumbleMbedtlsNetwork *net = MUMBLE_MBEDTLS_NETWORK (self);

  uint8_t *current = buffer;
  int ret = 0;
  size_t n_read = 0;
  while (n_read < length)
    {
      ret = mbedtls_ssl_read (&net->ssl, current, length - n_read);
      if (ret <= 0)
        {
          g_set_error (err, MUMBLE_NETWORK_ERROR, MUMBLE_NETWORK_ERROR_FAIL,
                       "mbedtls_ssl_read returned %d (-0x%04x)", ret, -ret);
          return;
        }
      n_read += ret;
      current += ret;
    }
}

void
mumble_mbedtls_network_write_bytes (MumbleNetwork *self,
                                    const guint8 *buffer, size_t length,
                                    GError **err)
{
  g_return_if_fail (self != NULL);
  g_return_if_fail (buffer != NULL);
  g_return_if_fail (length > 0);
  g_return_if_fail (err == NULL || *err == NULL);
  MumbleMbedtlsNetwork *net = MUMBLE_MBEDTLS_NETWORK (self);

  uint8_t *current = (uint8_t *) buffer;
  int ret = 0;
  size_t n_written = 0;
  while (n_written < length)
    {
      ret = mbedtls_ssl_write (&net->ssl, current, length - n_written);
      if (ret <= 0)
        {
          g_set_error (err, MUMBLE_NETWORK_ERROR, MUMBLE_NETWORK_ERROR_FAIL,
                       "mbedtls_ssl_write returned %d (-0x%04x)", ret, -ret);
          return;
        }
      n_written += ret;
      current += ret;
    }
}
