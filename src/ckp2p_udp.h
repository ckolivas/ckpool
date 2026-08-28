/*
 * Copyright 2026 Con Kolivas
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 3 of the License, or (at your option)
 * any later version.  See COPYING for more details.
 */

#ifndef CKP2P_UDP_H
#define CKP2P_UDP_H

#include "ckp2p.h"
#include "ckp2p_fec.h"

#define P2P_UDP_MAXPKT	1400
#define P2P_UDP_HDR	44
#define P2P_UDP_UA	"/ckp2p:2.0/"

int p2p_udp_init(int port);
int p2p_udp_fd(void);
void p2p_udp_set_magic(const uchar magic[4]);
void p2p_udp_set_genesis(const uchar genesis[32]);

bool p2p_udp_fill_dst(p2p_conn_t *conn, const char *host, int port);
void p2p_udp_canon_ip(const struct sockaddr *sa, char *out, size_t outlen);
void p2p_udp_canon_ip_str(const char *host, char *out, size_t outlen);

bool p2p_udp_send(p2p_conn_t *conn, const char *cmd, const uchar *payload,
		  uint32_t plen);
bool p2p_udp_hello(p2p_conn_t *conn);
bool p2p_udp_hello_wait(p2p_conn_t *conn, int timeout_ms);
void p2p_udp_ping(p2p_conn_t *conn, uint64_t nonce);

void *p2p_udp_receiver(void *arg);

/* Implemented in ckp2p.c */
void p2p_handle_msg(p2p_conn_t *conn, const char *cmd, uchar *payload,
		    uint32_t plen);
p2p_conn_t *ckp2p_client_find(const char *ip);
void ckp2p_client_set(const char *ip, enum p2p_xport xport, p2p_conn_t *conn);
void ckp2p_client_drop_tcp(const char *ip, p2p_conn_t *keep);
p2p_conn_t *ckp2p_udp_bind_peer(const char *ip, const struct sockaddr *sa,
				socklen_t slen);

#endif
