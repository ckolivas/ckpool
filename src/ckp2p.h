/*
 * Copyright 2026 Con Kolivas
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 3 of the License, or (at your option)
 * any later version.  See COPYING for more details.
 */

typedef struct {
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
	int reconnect;
	int source;
} p2p_conn_t;

int prepare_ckp2p(ckpool_t *ckp);
void submit_compact_block(ckpool_t *ckp, const uchar *blockhash, uchar *cmpct_payload,
			  uint32_t cmpct_len, uint64_t shortid_nonce);
