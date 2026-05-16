/*
 * Copyright 2026 Con Kolivas
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 3 of the License, or (at your option)
 * any later version.  See COPYING for more details.
 */

#include "libckpool.h"
#include "sha2.h"
#include "ckpool.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <string.h>
#include <stdlib.h>
#include <endian.h>

#define MSG_BLOCK 2
#define MSG_WITNESS_FLAG (1U << 30)
#define MSG_WITNESS_BLOCK (MSG_BLOCK | MSG_WITNESS_FLAG)
#define MSG_CMPCT_BLOCK 4
#define KEEPALIVE_INTERVAL 60

static const struct {
	const char *name;
	int port;
	uchar magic[4];
	uchar genesis[32];
} netdefs[] = {
	{"mainnet",  8333, {0xf9, 0xbe, 0xb4, 0xd9}, {0x6f,0xe2,0x8c,0x0a,0xb6,0xf1,0xb3,0x72,0xc1,0xa6,0xa2,0x46,0xae,0x63,0xf7,0x4f,0x93,0x1e,0x83,0x65,0xe1,0x5a,0x08,0x9c,0x68,0xd6,0x19,0x00,0x00,0x00,0x00,0x00}},
	{"testnet", 18333, {0x0b, 0x11, 0x09, 0x07}, {0x43,0x49,0x7f,0xd7,0xf8,0x26,0x95,0x71,0x08,0xf4,0xa3,0x0f,0xd9,0xce,0xc3,0xae,0xba,0x79,0x97,0x20,0x84,0xe9,0x0e,0xad,0x01,0xea,0x33,0x09,0x00,0x00,0x00,0x00}},
	{"testnet4", 48333, {0x1c, 0x16, 0x3f, 0x28}, {0x43,0xf0,0x8b,0xda,0xb0,0x50,0xe3,0x5b,0x56,0x7c,0x86,0x4b,0x91,0xf4,0x7f,0x50,0xae,0x72,0x5a,0xe2,0xde,0x53,0xbc,0xfb,0xba,0xf2,0x84,0xda,0x00,0x00,0x00,0x00}},
	{"signet",  38333, {0x40, 0xcf, 0x03, 0x0a}, {0xdd,0x46,0x00,0x7f,0x9c,0x9d,0x8d,0x56,0xc7,0xd2,0xf5,0xa0,0xd4,0x96,0x6d,0x49,0x02,0x5f,0xdf,0xff,0x95,0x2c,0x42,0x25,0xe9,0x73,0x98,0x81,0x08,0x00,0x00,0x00}},
	{"regtest", 18444, {0xfa, 0xbf, 0xb5, 0xda}, {0x0f,0x91,0x88,0xf1,0x3c,0xb7,0xb2,0xc7,0x1f,0x2a,0x33,0x5e,0x3a,0x4f,0xc3,0x28,0xbf,0x5b,0xeb,0x43,0x60,0x12,0xaf,0xca,0x59,0x0b,0x1a,0x11,0x46,0x6e,0x22,0x06}},
	{NULL, 0, {0}, {0}}
};

static struct current_block {
	uchar hash[32];
	cklock_t lock;
	uchar *txns;
} curblock;

/* Check if magic is unset (all zeros) */
static bool magic_unset(const uchar m[4])
{
	return m[0] == 0 && m[1] == 0 && m[2] == 0 && m[3] == 0;
}

static int64_t parse_varint(const uchar *data, uint32_t dlen, uint32_t *pos)
{
	if (*pos >= dlen)
		return -1;
	uchar c = data[(*pos)++];
	if (c < 0xfd)
		return c;
	if (c == 0xfd) {
		uint16_t v_le, v;

		if (*pos + 2 > dlen)
			return -1;
		memcpy(&v_le, data + *pos, 2);
		v = le16toh(v_le);
		*pos += 2;
		return v;
	} else if (c == 0xfe) {
		uint32_t v_le, v;

		if (*pos + 4 > dlen)
			return -1;
		memcpy(&v_le, data + *pos, 4);
		v = le32toh(v_le);
		*pos += 4;
		return v;
	} else {
		uint64_t v_le, v;

		if (*pos + 8 > dlen)
			return -1;
		memcpy(&v_le, data + *pos, 8);
		v = le64toh(v_le);
		*pos += 8;
		return v;
	}
}

static void double_sha256_4(uchar chksum[4], const uchar *data, size_t len)
{
	uchar h1[32], h2[32];
	sha256(data, (unsigned int)len, h1);
	sha256(h1, 32, h2);
	memcpy(chksum, h2, 4);
}

/* Read exactly len bytes (loops on partial reads) */
static ssize_t read_exact(int sock, void *buf, size_t len)
{
	size_t left = len;
	char *p = buf;

	while (left > 0) {
		ssize_t n = read(sock, p, left);
		if (n <= 0) {
			if (n == 0)
				LOGINFO("P2P Peer closed connection");
			else
				LOGINFO("P2P read error: %s", strerror(errno));
			return n;
		}
		left -= n;
		p += n;
	}
	return (ssize_t)len;
}

/* Write exactly len bytes (loops on partial writes) */
static ssize_t write_exact(int sock, const void *buf, size_t len)
{
	size_t left = len;
	const char *p = buf;

	while (left > 0) {
		ssize_t n = write(sock, p, left);
		if (n <= 0) {
			if (n == 0)
				LOGINFO("P2P write: peer closed connection");
			else
				LOGERR("P2P write error: %s", strerror(errno));
			return n;
		}
		left -= n;
		p += n;
	}
	return (ssize_t)len;
}

static void p2p_send(p2p_conn_t *conn, const char *cmd, const uchar *payload, uint32_t plen)
{
	uchar hdr[24];
	uchar chksum[4];
	uint32_t plen_le;

	memcpy(hdr, conn->magic, 4);
	memset(hdr + 4, 0, 12);
	strncpy((char *)(hdr + 4), cmd, 12);
	plen_le = htole32(plen);
	memcpy(hdr + 16, &plen_le, 4);

	if (plen == 0) {
		static const uchar empty_chksum[4] = {0x5d, 0xf6, 0xe0, 0xe2};
		memcpy(chksum, empty_chksum, 4);
	} else {
		double_sha256_4(chksum, payload, plen);
	}
	memcpy(hdr + 20, chksum, 4);

	if (write_exact(conn->sock, hdr, 24) != 24 ||
		(plen && write_exact(conn->sock, payload, plen) != (ssize_t)plen)) {
		LOGERR("p2p_send(%s) failed", cmd);
		} else {
			LOGINFO("Sent %s (%u bytes)", cmd, plen);
		}
}

static bool p2p_recv(p2p_conn_t *conn, char cmd[13], uchar **payload, uint32_t *plen)
{
	uchar hdr[24];
	uchar rec_magic[4];
	uchar rec_chksum[4];
	uint32_t plen_le;

	if (read_exact(conn->sock, hdr, 24) != 24) {
		return false;
	}

	memcpy(rec_magic, hdr, 4);
	if (magic_unset(conn->magic)) {
		memcpy(conn->magic, rec_magic, 4);
		LOGINFO("Auto-detected network magic %02x%02x%02x%02x", rec_magic[0], rec_magic[1], rec_magic[2], rec_magic[3]);
	} else if (memcmp(rec_magic, conn->magic, 4)) {
		LOGERR("Magic mismatch");
		return false;
	}

	memcpy(cmd, hdr + 4, 12); cmd[12] = 0;
	memcpy(&plen_le, hdr + 16, 4);
	*plen = le32toh(plen_le);
	memcpy(rec_chksum, hdr + 20, 4);

	if (*plen == 0) {
		static const uchar empty_chksum[4] = {0x5d, 0xf6, 0xe0, 0xe2};
		*payload = NULL;
		if (memcmp(rec_chksum, empty_chksum, 4)) {
			LOGERR("Checksum fail on %s (empty)", cmd);
			return false;
		}
		return true;
	}

	*payload = ckalloc(*plen);

	if (read_exact(conn->sock, *payload, *plen) != (ssize_t)*plen) {
		dealloc(*payload);
		*payload = NULL;
		return false;
	}

	uchar calc_chksum[4];
	double_sha256_4(calc_chksum, *payload, *plen);
	if (memcmp(calc_chksum, rec_chksum, 4)) {
		LOGERR("Checksum fail on %s", cmd);
		dealloc(*payload);
		*payload = NULL;
		return false;
	}
	return true;
}

static void handle_ping(p2p_conn_t *conn, uchar *payload, uint32_t len)
{
	if (len == 8)
		p2p_send(conn, "pong", payload, len);
	if (payload)
		dealloc(payload);
}

static void handle_sendcmpct(p2p_conn_t *conn, uchar *payload, uint32_t len)
{
	if (len == 9) {
		bool announce = (payload[0] != 0);
		uint64_t ver_le, ver;

		memcpy(&ver_le, payload + 1, 8);
		ver = le64toh(ver_le);
		if (ver == 1 || ver == 2) {
			conn->high_bw = announce;
			LOGINFO("Peer SENDCMPCT v%llu high-bw=%d", (unsigned long long)ver, conn->high_bw);
		}
	}
	if (payload)
		dealloc(payload);
}

static void send_notfound(p2p_conn_t *conn, uint32_t type, uchar *hash)
{
	uint32_t type_le;
	uchar nf_payload[37];

	nf_payload[0] = 1;
	type_le = htole32(type);
	memcpy(nf_payload + 1, &type_le, 4);
	memcpy(nf_payload + 5, hash, 32);
	p2p_send(conn, "notfound", nf_payload, 37);
}

static void handle_getdata(p2p_conn_t *conn, uchar *payload, uint32_t plen)
{
	uint32_t pos = 0;
	int64_t count = parse_varint(payload, plen, &pos);
	bool new_block = false;

	if (count < 0 || count > 500) { // basic sanity
		dealloc(payload);
		return;
	}
	for (int64_t i = 0; i < count; i++) {
		uint32_t type_le, type;
		bool responded = false;
		uchar hash[32];

		if (pos + 36 > plen)
			break;
		memcpy(&type_le, payload + pos, 4);
		type = le32toh(type_le);
		pos += 4;
		memcpy(hash, payload + pos, 32);
		pos += 32;
		if (type != MSG_CMPCT_BLOCK) {
			send_notfound(conn, type, hash);
			continue;
		}

		ck_wlock(&curblock.lock);
		if (memcmp(curblock.hash, hash, 32)) {
			memcpy(curblock.hash, hash, 32);
			new_block = true;
		}
		ck_wunlock(&curblock.lock);

		if (new_block) {
			char *blockhash = bin2hex(hash, 32);

			LOGWARNING("New block hash detected: %s", blockhash);
			free(blockhash);
		}

		ck_rlock(&conn->block_lock);
		if (conn->has_block && !memcmp(conn->blockhash, hash, 32)) {
			p2p_send(conn, "cmpctblock", conn->cmpct_payload, conn->cmpct_len);
			responded = true;
		}
		ck_runlock(&conn->block_lock);

		if (!responded)
			send_notfound(conn, type, hash);
	}
	dealloc(payload);
}

static void handle_getblocktxn(p2p_conn_t *conn, uchar *payload, uint32_t plen)
{
	uint32_t type, type_le;

	if (plen < 32) {
		dealloc(payload);
		return;
	}
	uchar nf_payload[37];
	nf_payload[0] = 1;
	type = MSG_BLOCK;
	type_le = htole32(type);
	memcpy(nf_payload + 1, &type_le, 4);
	memcpy(nf_payload + 5, payload, 32); // blockhash
	p2p_send(conn, "notfound", nf_payload, 37);
	LOGDEBUG("GETBLOCKTXN - sent NOTFOUND for block");
	dealloc(payload);
}

static void handle_inv(p2p_conn_t *conn, uchar *payload, uint32_t plen)
{
	uint32_t pos = 0;
	bool has_block = false;
	int64_t i, count = parse_varint(payload, plen, &pos);

	if (count < 0 || count > 500) {
		dealloc(payload);
		return;
	}
	for (i = 0; i < count; i++) {
		uint32_t type_le, type;

		if (pos + 36 > plen)
			break;
		memcpy(&type_le, payload + pos, 4);
		type = le32toh(type_le);
		pos += 4;
		uchar hash[32];
		memcpy(hash, payload + pos, 32);
		pos += 32;
		if (type == MSG_BLOCK || type == MSG_WITNESS_BLOCK) {
			uint32_t req_type = MSG_CMPCT_BLOCK;
			uint32_t req_type_le = htole32(req_type);

			has_block = true;
			uchar getdata_payload[37];
			getdata_payload[0] = 1;
			memcpy(getdata_payload + 1, &req_type_le, 4);
			memcpy(getdata_payload + 5, hash, 32);
			p2p_send(conn, "getdata", getdata_payload, 37);
		}
	}
	if (has_block)
		LOGINFO("Received INV (%u bytes) - requesting cmpctblock for blocks", plen);
	else
		LOGDEBUG("Received INV (%u bytes) - ignoring transaction announcements", plen);
	dealloc(payload);
}

static void relay_compact_block(ckpool_t *ckp, const uchar *blockhash, uchar *cmpct_payload,
				uint32_t cmpct_len, uint64_t shortid_nonce, int source);

/* Function for testing cmpctblock validity by echoing back any received */
static void handle_cmpctblock(ckpool_t *ckp, uchar *payload, uint32_t plen, int source)
{
	uint64_t shortid_nonce_le, shortid_nonce;

	if (plen < 88) {
		dealloc(payload);
		return;
	}
	uchar header[80];
	memcpy(header, payload, 80);
	uchar h1[32], blockhash[32];
	sha256(header, 80, h1);
	sha256(h1, 32, blockhash);
	memcpy(&shortid_nonce_le, payload + 80, 8);
	shortid_nonce = le64toh(shortid_nonce_le);
	relay_compact_block(ckp, blockhash, payload, plen, shortid_nonce, source);
	/* payload is stolen and released by relay_compact_block */
}

static bool p2p_connect_socket(p2p_conn_t *conn)
{
	conn->sock = connect_socket(conn->host, conn->charport);
	if (conn->sock < 0) {
		LOGINFO("connect_socket failed in p2p_connect_socket");
		return false;
	}
	LOGNOTICE("ckp2p connected to %s:%d (%s)", conn->host, conn->port, conn->netname);

	return true;
}

static bool do_handshake(p2p_conn_t *conn, int port);

struct p2pendpoint {
	ckpool_t *ckp;
	pthread_t reader_thread;
	pthread_t keepalive_thread;
	p2p_conn_t *conn;
	int source;
};

typedef struct p2pendpoint p2pendpoint_t;

static void *p2p_reader(void *arg)
{
	p2pendpoint_t *p2pe = arg;
	p2p_conn_t *conn = p2pe->conn;
	char cmd[13];
	uchar *payload;
	uint32_t plen;

	pthread_detach(pthread_self());
	rename_proc("ckp2pr");

	conn->reconnect = 5;

	while (42) {
		if (conn->sock < 0) {
			if (p2p_connect_socket(conn)) {
				if (!do_handshake(conn, conn->port)) {
					close(conn->sock);
					conn->sock = -1;
				}
			}
			if (conn->sock < 0) {
				if (conn->reconnect < 300)
					conn->reconnect *= 2;
				sleep(conn->reconnect);
				continue;
			}
		}

		if (!p2p_recv(conn, cmd, &payload, &plen)) {
			LOGINFO("P2P recv failed - disconnecting");
			close(conn->sock);
			conn->sock = -1;
			conn->handshake_done = false;
			if (conn->reconnect < 300)
				conn->reconnect *= 2;
			sleep(conn->reconnect);
			continue;
		}

		conn->reconnect = 5;
		// Log all received messages with descriptive type, even if ignoring
		if (!strcmp(cmd, "version")) {
			LOGINFO("Received VERSION (%u bytes) - handling for handshake", plen);
		} else if (!strcmp(cmd, "verack")) {
			LOGINFO("Received VERACK (%u bytes) - handling for handshake", plen);
		} else if (!strcmp(cmd, "ping")) {
			LOGINFO("Received PING (%u bytes) - replying with PONG", plen);
			handle_ping(conn, payload, plen);
			continue; // Skip dealloc since handler does it
		} else if (!strcmp(cmd, "pong")) {
			LOGDEBUG("Received PONG (%u bytes) - ignoring (keep-alive response)", plen);
		} else if (!strcmp(cmd, "sendcmpct")) {
			LOGINFO("Received SENDCMPCT (%u bytes) - handling compact block negotiation", plen);
			handle_sendcmpct(conn, payload, plen);
			continue; // Skip dealloc since handler does it
		} else if (!strcmp(cmd, "getdata")) {
			LOGINFO("Received GETDATA (%u bytes) - handling (request for compact block or tx)", plen);
			handle_getdata(conn, payload, plen);
			continue; // Skip dealloc since handler does it
		} else if (!strcmp(cmd, "getblocktxn")) {
			LOGINFO("Received GETBLOCKTXN (%u bytes) - handling (request for block txn)", plen);
			handle_getblocktxn(conn, payload, plen);
			continue; // Skip dealloc since handler does it
		} else if (!strcmp(cmd, "inv")) {
			handle_inv(conn, payload, plen);
			continue;
		} else if (!strcmp(cmd, "headers")) {
			LOGDEBUG("Received HEADERS (%u bytes) - ignoring (block headers announcement)", plen);
		} else if (!strcmp(cmd, "cmpctblock")) {
			LOGNOTICE("Received CMPCTBLOCK (%u bytes) - handling (resend to all nodes)", plen);
			handle_cmpctblock(p2pe->ckp, payload, plen, p2pe->source);
			continue;
			LOGINFO("Received CMPCTBLOCK (%u bytes) - ignoring (compact block data)", plen);
		} else if (!strcmp(cmd, "tx")) {
			LOGDEBUG("Received TX (%u bytes) - ignoring (transaction data)", plen);
		} else if (!strcmp(cmd, "block")) {
			LOGINFO("Received BLOCK (%u bytes) - ignoring (full block data)", plen);
		} else if (!strcmp(cmd, "blocktxn")) {
			LOGDEBUG("Received BLOCKTXN (%u bytes) - ignoring (block transactions response)", plen);
		} else if (!strcmp(cmd, "getheaders")) {
			LOGDEBUG("Received GETHEADERS (%u bytes) - ignoring (headers request)", plen);
		} else if (!strcmp(cmd, "getblocks")) {
			LOGDEBUG("Received GETBLOCKS (%u bytes) - ignoring (blocks request)", plen);
		} else if (!strcmp(cmd, "getaddr")) {
			LOGDEBUG("Received GETADDR (%u bytes) - ignoring (peer discovery request)", plen);
		} else if (!strcmp(cmd, "addr")) {
			LOGDEBUG("Received ADDR (%u bytes) - ignoring (peer addresses)", plen);
		} else if (!strcmp(cmd, "addrv2")) {
			LOGDEBUG("Received ADDRV2 (%u bytes) - ignoring (peer addresses v2)", plen);
		} else if (!strcmp(cmd, "feefilter")) {
			LOGDEBUG("Received FEEFILTER (%u bytes) - ignoring (fee filter)", plen);
		} else if (!strcmp(cmd, "reject")) {
			LOGDEBUG("Received REJECT (%u bytes) - ignoring (rejection message)", plen);
		} else if (!strcmp(cmd, "notfound")) {
			LOGDEBUG("Received NOTFOUND (%u bytes) - ignoring (item not found)", plen);
		} else if (!strcmp(cmd, "wtxidrelay")) {
			LOGDEBUG("Received WTXIDRELAY (%u bytes) - ignoring (wtxid relay negotiation)", plen);
		} else if (!strcmp(cmd, "sendaddrv2")) {
			LOGDEBUG("Received SENDADDRV2 (%u bytes) - ignoring (addrv2 negotiation)", plen);
		} else {
			LOGINFO("Received unknown command %s (%u bytes) - ignoring", cmd, plen);
		}

		if (payload) dealloc(payload);
	}
	return NULL;
}

static void *p2p_keepalive(void *arg)
{
	p2pendpoint_t *p2pe = arg;
	p2p_conn_t *conn = p2pe->conn;

	pthread_detach(pthread_self());
	rename_proc("ckp2pk");

	while (42) {
		uint64_t nonce, nonce_le;

		sleep(KEEPALIVE_INTERVAL);
		if (!conn->handshake_done || conn->sock < 0)
			continue;

		nonce = ((uint64_t)rand() << 32) | rand();
		nonce_le = htole64(nonce);
		p2p_send(conn, "ping", (uchar *)&nonce_le, 8);
	}
	return NULL;
}

static bool do_handshake(p2p_conn_t *conn, int port)
{
	uint32_t nversion, nversion_le, height, height_le, protover, protover_le;
	uchar version_payload[97] = {};
	int off = 0;
	uint64_t services, services_le, ntime, ntime_le, recv_services, recv_services_le,
	from_services_le, nnonce, nnonce_le;
	uint16_t recv_port, from_port;
	// user_agent
	const char *ua = "/ckp2p:1.0/";
	char cmd[13];
	uchar *payload;
	uint32_t plen;

	nversion = 70016;
	nversion_le = htole32(nversion);
	memcpy(version_payload + off, &nversion_le, sizeof(nversion_le));
	off += sizeof(nversion_le);

	services = 9ULL;
	services_le = htole64(services);
	memcpy(version_payload + off, &services_le, sizeof(services_le));
	off += sizeof(services_le);

	ntime = (uint64_t)time(NULL);
	ntime_le = htole64(ntime);
	memcpy(version_payload + off, &ntime_le, sizeof(ntime_le));
	off += sizeof(ntime_le);

	// addr_recv: services 9, IPv4-mapped 127.0.0.1, port
	recv_services = services;
	recv_services_le = htole64(recv_services);
	memcpy(version_payload + off, &recv_services_le, sizeof(recv_services_le));
	off += sizeof(recv_services_le);
	uchar recv_ip[16] = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xff,0xff,0x7f,0x00,0x00,0x01};
	memcpy(version_payload + off, recv_ip, 16);
	off += 16;
	recv_port = htons(port); // Ports are big-endian
	memcpy(version_payload + off, &recv_port, sizeof(recv_port));
	off += sizeof(recv_port);

	// addr_from: services 9, all zeros ip, port 0 (dummy to prevent self-connection)
	from_services_le = htole64(services);
	memcpy(version_payload + off, &from_services_le, sizeof(from_services_le));
	off += sizeof(from_services_le);
	memset(version_payload + off, 0, 16); // ip all zero
	off += 16;
	from_port = htons(0);
	memcpy(version_payload + off, &from_port, sizeof(from_port));
	off += sizeof(from_port);

	// nonce: random
	nnonce = ((uint64_t)rand() << 32) | rand();
	nnonce_le = htole64(nnonce);
	memcpy(version_payload + off, &nnonce_le, sizeof(nnonce_le));
	off += sizeof(nnonce_le);

	uchar ualen = (uchar)strlen(ua);
	version_payload[off++] = ualen;
	memcpy(version_payload + off, ua, ualen);
	off += ualen;

	// start_height: 0
	height = 0;
	height_le = htole32(height);
	memcpy(version_payload + off, &height_le, sizeof(height_le));
	off += sizeof(height_le);

	// relay: 0 (to enable TX relay and unsolicited INV/TX)
	version_payload[off++] = 0;

	p2p_send(conn, "version", version_payload, sizeof(version_payload));

	LOGINFO("Waiting for VERSION from peer...");

	while (42) {
		if (!p2p_recv(conn, cmd, &payload, &plen))
			return false;
		LOGINFO("Received %s (%u bytes)", cmd, plen);
		if (!strcmp(cmd, "version")) {
			LOGINFO("Received VERSION from peer");
			dealloc(payload);
			break;
		}
		if (payload)
			dealloc(payload);
	}

	p2p_send(conn, "wtxidrelay", NULL, 0);
	p2p_send(conn, "sendaddrv2", NULL, 0);

	uchar sc[9] = {0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}; // high_bw=1, ver=2
	p2p_send(conn, "sendcmpct", sc, 9);

	p2p_send(conn, "verack", NULL, 0);

	while (42) {
		if (!p2p_recv(conn, cmd, &payload, &plen))
			return false;
		LOGINFO("Received %s (%u bytes)", cmd, plen);
		if (!strcmp(cmd, "verack")) {
			LOGINFO("Received VERACK - handshake complete");
			dealloc(payload);
			break;
		}
		if (payload)
			dealloc(payload);
	}

	conn->handshake_done = true;
	LOGNOTICE("P2P handshake complete on %s - ready for compact blocks", conn->netname);

	// Send getheaders with genesis locator and zero stop to request up to 2000 headers
	uchar gethdr_payload[69];
	memset(gethdr_payload, 0, sizeof(gethdr_payload));
	protover = 70016;
	protover_le = htole32(protover);
	memcpy(gethdr_payload, &protover_le, 4);
	gethdr_payload[4] = 1; // hash_count varint=1
	memcpy(gethdr_payload + 5, conn->genesis, 32);
	// hash_stop remains all zeros
	p2p_send(conn, "getheaders", gethdr_payload, sizeof(gethdr_payload));

	return true;
}

struct compact_block {
	pthread_t pth;
	ckpool_t *ckp;
	uchar blockhash[32];
	uchar *cmpct_payload;
	uint32_t cmpct_len;
	uint64_t shortid_nonce;
	int source;
};

typedef struct compact_block compact_block_t;

static void *submission_thread(void *arg)
{
	compact_block_t *cbt = arg;
	int i, submitted = 0;
	char *hex;

	pthread_detach(pthread_self());

	for (i = 0; i < cbt->ckp->p2purls; i++) {
		p2p_conn_t *conn;

		if (i == cbt->source) {
			LOGDEBUG("Skipping relaying compact block to source node %d", i);
			continue;
		}

		conn = cbt->ckp->p2pconn[i];
		if (unlikely(!conn)) {
			LOGDEBUG("Skipping relaying compact block to uninitialised node %d", i);
			continue;
		}

		if (!memcmp(conn->blockhash, cbt->blockhash, 32)) {
			LOGINFO("Source node %d already has compact block", i);
			continue;
		}

		if (conn->sock < 0 || !conn->handshake_done) {
			LOGINFO("Connection %d not active - skipping submission", i);
			continue;
		}

		ck_wlock(&conn->block_lock);
		if (conn->cmpct_payload)
			dealloc(conn->cmpct_payload);
		memcpy(conn->blockhash, cbt->blockhash, 32);
		conn->cmpct_payload = ckalloc(cbt->cmpct_len);
		memcpy(conn->cmpct_payload, cbt->cmpct_payload, cbt->cmpct_len);
		conn->cmpct_len = cbt->cmpct_len;
		conn->shortid_nonce = cbt->shortid_nonce;
		conn->has_block = true;
		ck_wunlock(&conn->block_lock);

		p2p_send(conn, "cmpctblock", cbt->cmpct_payload, cbt->cmpct_len);
		submitted++;
	}

	hex = bin2hex(cbt->blockhash, 32);
	if (submitted)
		LOGNOTICE("Submitted %d compact block%s %s", submitted, submitted > 1 ? "s" : "", hex);
	free(cbt->cmpct_payload);
	free(cbt);
	free(hex);

	return NULL;
}

static void relay_compact_block(ckpool_t *ckp, const uchar *blockhash, uchar *cmpct_payload,
				uint32_t cmpct_len, uint64_t shortid_nonce, int source)
{
	compact_block_t *cbt = ckalloc(sizeof(compact_block_t));

	cbt->ckp = ckp;
	memcpy(cbt->blockhash, blockhash, 32);
	/* Steal payload memory here */
	cbt->cmpct_payload = cmpct_payload;
	cbt->cmpct_len = cmpct_len;
	cbt->shortid_nonce = shortid_nonce;
	cbt->source = source;

	create_pthread(&cbt->pth, submission_thread, cbt);
}

void submit_compact_block(ckpool_t *ckp, const uchar *blockhash, uchar *cmpct_payload,
			  uint32_t cmpct_len, uint64_t shortid_nonce)
{
	relay_compact_block(ckp, blockhash, cmpct_payload, cmpct_len, shortid_nonce, -1);
}

static p2p_conn_t *ckp2p_connect(ckpool_t *ckp, const char *host, const char *charport, int source)
{
	p2p_conn_t *conn = ckzalloc(sizeof(*conn));
	p2pendpoint_t *p2pe;
	bool success = true;
	int port, i;

	cklock_init(&conn->block_lock);
	conn->cmpct_payload = NULL;
	conn->has_block = false;
	conn->sock = -1;
	strncpy(conn->host, host, sizeof(conn->host) - 1);
	strncpy(conn->charport, charport, sizeof(conn->charport) - 1);
	sscanf(charport, "%d", &port);
	conn->port = port;
	memset(conn->magic, 0, 4); // unset

	for (i = 0; netdefs[i].name; i++) {
		if (netdefs[i].port == port) {
			memcpy(conn->magic, netdefs[i].magic, 4);
			memcpy(conn->genesis, netdefs[i].genesis, 32);
			conn->netname = netdefs[i].name;
			break;
		}
	}
	if (!conn->netname) {
		memcpy(conn->magic, netdefs[0].magic, 4);
		memcpy(conn->genesis, netdefs[0].genesis, 32);
		conn->netname = netdefs[0].name;
	}

	if (!p2p_connect_socket(conn))
		success = false;

	if (success && !do_handshake(conn, port))
		success = false;

	if (!success) {
		LOGWARNING("ckp2p Failed to connect to bitcoin node %d - %s:%s, deferring",
			   source, host, charport);
		if (conn->sock >= 0)
			close(conn->sock);
		conn->sock = -1;
	} else
		LOGWARNING("ckp2p connected to bitcoin node %d - %s:%s", source, host, charport);

	p2pe = ckzalloc(sizeof(p2pendpoint_t));
	p2pe->ckp = ckp;
	p2pe->conn = conn;
	p2pe->source = source;

	create_pthread(&p2pe->reader_thread, p2p_reader, p2pe);

	create_pthread(&p2pe->keepalive_thread, p2p_keepalive, p2pe);

	return conn;
}

int prepare_ckp2p(ckpool_t *ckp)
{
	connsock_t *cs;
	int i;

	cklock_init(&curblock.lock);

	ckp->p2pconn = ckzalloc(sizeof(p2p_conn_t *) * ckp->p2purls);
	ckp->p2pcs = ckzalloc(sizeof(connsock_t *) * ckp->p2purls);
	for (i = 0 ; i < ckp->p2purls ; i++) {
		ckp->p2pcs[i] = ckzalloc(sizeof(connsock_t));
		cs = ckp->p2pcs[i];
		if (!extract_sockaddr(ckp->p2purl[i], &cs->url, &cs->port)) {
			LOGEMERG("Failed to extract address from p2purl %s", ckp->p2purl[i]);
			return -1;
		}
	}

	for (i = 0 ; i < ckp->p2purls ; i++) {
		cs = ckp->p2pcs[i];
		ckp->p2pconn[i] = ckp2p_connect(ckp, cs->url, cs->port, i);
	}
	LOGWARNING("ckp2p finished attempting bitcoin node connections.");

	return 0;
}
