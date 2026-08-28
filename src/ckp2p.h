/*
 * Copyright 2026 Con Kolivas
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 3 of the License, or (at your option)
 * any later version.  See COPYING for more details.
 */
#ifndef CKP2P_H
#define CKP2P_H

#include "uthash.h"
#include <netinet/in.h>

struct p2p_conn;

enum p2p_xport {
	P2P_XPORT_TCP = 0,
	P2P_XPORT_UDP = 1
};

struct ckp2p_client {
	UT_hash_handle hh;
	char ip[INET6_ADDRSTRLEN];
	enum p2p_xport xport;
	struct p2p_conn *conn;
};

typedef struct ckp2p_client ckp2p_client_t;

struct peerlist {
	UT_hash_handle hh;
	char url[288];
	struct p2p_conn *conn;
};

typedef struct peerlist peerlist_t;

struct p2p_conn {
	int sock;
	uchar magic[4];
	uchar genesis[32];
	const char *netname;
	bool handshake_done;
	bool high_bw;
	cklock_t block_lock;
	uchar blockhash[32];
	uchar *cmpct_payload;
	uint32_t cmpct_len;
	uint64_t shortid_nonce;
	bool has_block;
	char host[256];
	char charport[32];
	int port;
	int peer;
	tv_t last_alive;
	tv_t last_attempt;
	int reconnect;
	bool evicted;
	bool incoming_only;
	bool active;
	bool udp;
	bool ckp2p_peer;
	struct sockaddr_storage udp_dst;
	socklen_t udp_dstlen;
	uint64_t udp_hello_nonce;
	bool udp_hello_acked;
	peerlist_t *p2ppeer;
};

typedef struct p2p_conn p2p_conn_t;

int prepare_ckp2p(void);
void submit_compact_block(const uchar *blockhash, uchar *cmpct_payload,
			  uint32_t cmpct_len, uint64_t shortid_nonce);
void p2p_mark_alive(p2p_conn_t *conn);

#endif /* CKP2P_H */
