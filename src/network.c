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

#include <arpa/inet.h>
#include <string.h>

#include "utils.h"
#include "network_private.h"

static const char pers[] = "cmumble";

cmumble_network* cmumble_network_init ()
{
	cmumble_network* net = calloc(1, sizeof(cmumble_network));
	
	mbedtls_net_init(&net->server_fd);
	mbedtls_ssl_init(&net->ssl);
	mbedtls_ssl_config_init(&net->conf);
	mbedtls_x509_crt_init(&net->cacert);
	mbedtls_ctr_drbg_init(&net->ctr_drbg);
	mbedtls_entropy_init(&net->entropy);

	int ret;
	if((ret = mbedtls_ctr_drbg_seed(&net->ctr_drbg, mbedtls_entropy_func,
	                                &net->entropy, (const uint8_t*) pers,
	                                strlen(pers))) != 0)
	{
		exit_with_message(10,
		                  " failed\n  ! mbedtls_ctr_drbg_seed returned %d\n",
		                  ret);
	}
	return net;
}

static void my_debug(void *ctx, int level, const char *file, int line,
                     const char *str)
{
	((void)level);
	fprintf((FILE *)ctx, "%s:%04d: %s", file, line, str);
	fflush((FILE *)ctx);
}

void cmumble_network_connect (cmumble_network* net, const char* server_name,
                              const char* server_port)
{
	int ret = 0;
	if((ret = mbedtls_net_connect(&net->server_fd, server_name, server_port,
	                              MBEDTLS_NET_PROTO_TCP)) != 0)
	{
		printf( " failed\n  ! mbedtls_net_connect returned %d\n\n", ret );
		exit(-2);
	}

	if((ret = mbedtls_ssl_config_defaults(&net->conf, MBEDTLS_SSL_IS_CLIENT,
	                                      MBEDTLS_SSL_TRANSPORT_STREAM,
	                                      MBEDTLS_SSL_PRESET_DEFAULT)) != 0)
	{
		printf(" failed\n  ! mbedtls_ssl_config_defaults returned %d\n\n",
		       ret);
		exit(-3);
	}

	mbedtls_ssl_conf_authmode(&net->conf, MBEDTLS_SSL_VERIFY_NONE);

	mbedtls_ssl_conf_rng(&net->conf, mbedtls_ctr_drbg_random, &net->ctr_drbg);
	mbedtls_ssl_conf_dbg(&net->conf, my_debug, stdout);

	if((ret = mbedtls_ssl_setup(&net->ssl, &net->conf)) != 0)
	{
		printf( " failed\n  ! mbedtls_ssl_setup returned %d\n\n", ret);
		exit(-7);
	}

	mbedtls_ssl_set_bio(&net->ssl, &net->server_fd, mbedtls_net_send, mbedtls_net_recv,
	                    NULL);

	while((ret = mbedtls_ssl_handshake(&net->ssl)) != 0)
	{
		if(ret != MBEDTLS_ERR_SSL_WANT_READ &&
		   ret != MBEDTLS_ERR_SSL_WANT_WRITE)
		{
			printf(" failed\n  ! mbedtls_ssl_handshake returned -0x%x\n\n",
			       -ret);
			exit(-8);
		}
	}
}

void cmumble_network_read_bytes(cmumble_network *net, uint8_t *buffer,
                                size_t length)
{
	uint8_t *current = buffer;
	int ret = 0;
	size_t n_read = 0;
	while(n_read < length)
	{
		ret = mbedtls_ssl_read(&net->ssl, current, length - n_read);
		if(ret <= 0)
		{
			exit_with_message(5, " failed\n  ! ssl_read returned %d\n\n", ret);
		}
		n_read += ret;
		current += ret;
	}
}

void cmumble_network_write_bytes(cmumble_network *net, const uint8_t *buffer,
                                 size_t length)
{
	uint8_t *current = (uint8_t *) buffer;
	int ret = 0;
	size_t n_written = 0;
	while(n_written < length)
	{
		ret = mbedtls_ssl_write(&net->ssl, current, length - n_written);
		if(ret <= 0)
		{
			exit_with_message(4, " failed\n  ! write returned %d\n\n", ret);
		}
		n_written += ret;
		current += ret;
	}
}

cmumble_packet_header cmumble_network_read_packet_header(cmumble_network *net)
{
	const int buffer_length = 6;
	uint8_t buffer[buffer_length];
	cmumble_network_read_bytes(net, buffer, buffer_length);
	cmumble_packet_header header = {
		ntohs(*(uint16_t*)buffer),
		ntohl(*(uint32_t*)(buffer + 2))
	};
	return header;
}

void cmumble_network_write_packet_header (cmumble_network *net, 
                                          const cmumble_packet_header *header)
{
	const int buffer_length = 6;
	uint8_t buffer[buffer_length];
	*(uint16_t*)buffer = htons(header->type);
	*(uint32_t*)(buffer + 2) = htonl(header->length);
	cmumble_network_write_bytes(net, (const uint8_t*) buffer, buffer_length);
}

void cmumble_network_free(cmumble_network* net)
{
	mbedtls_net_free(&net->server_fd);
	mbedtls_ssl_free(&net->ssl);
	mbedtls_ssl_config_free(&net->conf);
	// TODO: Check if there is a x509_crt_free and if it must be called?
	mbedtls_ctr_drbg_free(&net->ctr_drbg);
	mbedtls_entropy_free(&net->entropy);

	free(net);
}
