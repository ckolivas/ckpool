/*
 * Copyright 2026 Con Kolivas
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 3 of the License, or (at your option)
 * any later version.  See COPYING for more details.
 */

#include <sys/epoll.h>
#include <poll.h>
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
#include <stdio.h>

#include "libckpool.h"
#include "sha2.h"
#include "ckpool.h"
#include "utlist.h"
#include "uthash.h"

#define MSG_BLOCK 2
#define MSG_WITNESS_FLAG (1U << 30)
#define MSG_WITNESS_BLOCK (MSG_BLOCK | MSG_WITNESS_FLAG)
#define MSG_CMPCT_BLOCK 4
#define KEEPALIVE_INTERVAL 5
#define PING_INTERVAL 120
#define FAST_EVICT 600
#define EVICT_TIMEOUT 3600
#define P2P_LISTEN_PORT 8333
#define CKP2P_LISTEN_PORT 8335

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
} curblock;

static uint32_t externalip;
static int externalport;
static int total_conns;
static int active_conns;
static bool finished_init = false;
static cklock_t peerlock;
#define GENESIS_BITS 0x1d00ffff
static uint32_t current_bits = GENESIS_BITS;

static ckmsgq_t* p2p_readers;
static ckmsgq_t* p2p_connectors;
static int reader_epfd;
static int num_threads;

typedef struct blocklist {
	uchar hash[32];
	struct blocklist *next, *prev;
} blocklist_t;

static blocklist_t *blockhashes;

typedef struct wakelist {
	UT_hash_handle hh;
	int peer;
} wakelist_t;

static wakelist_t *reader_wakes, *connector_wakes;

static peerlist_t *p2ppeers;

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
				LOGNOTICE("P2P write error: %s", strerror(errno));
			return n;
		}
		left -= n;
		p += n;
	}
	return (ssize_t)len;
}

/* Parse the addr_from field from a VERSION message payload.
 * Returns true only if a valid IPv4 listening address AND port (>0) was extracted. */
static bool parse_version_addr_from(const uchar *payload, uint32_t plen,
                                    char *host_out, int *port_out)
{
	if (plen < 72)          /* minimum size for addr_from */
		return false;

	/* addr_from is always at byte offset 46 (after version+services+time+addr_recv) */
	const uchar *addr_from = payload + 46;

	/* services (8 bytes) inside net_addr */
	const uchar *ip = addr_from + 8;

	/* Port is big-endian at offset 16 of the net_addr */
	uint16_t port_be;
	memcpy(&port_be, ip + 16, 2);
	*port_out = ntohs(port_be);

	if (*port_out == 0 || *port_out > 65535)
		return false;

	/* IPv4-mapped address (::ffff:0.0.0.0/96) is the common case */
	static const uchar v4mapped[12] = {0,0,0,0,0,0,0,0,0,0,0xff,0xff};
	if (memcmp(ip, v4mapped, 12) == 0) {
		struct in_addr ipv4;
		memcpy(&ipv4.s_addr, ip + 12, 4);
		inet_ntop(AF_INET, &ipv4, host_out, INET_ADDRSTRLEN);
		if (!strncmp(host_out, "127", 3) || !strncmp(host_out, "192.168", 7) ||
		    !strncmp(host_out, "10.",3) || !strncmp(host_out, "172", 3) ||
		    !strncmp(host_out, "0.0.0.0", 7) || !strncmp(host_out, "169.254", 7)) {
			LOGDEBUG("Peer advertised LAN address %s", host_out);
			return false;
		}
		return true;
	}

	/* IPv6 not supported by ckp2p yet */
	return false;
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
		LOGNOTICE("p2p_send(%s) failed to peer %d", cmd, conn->peer);
	} else {
		tv_time(&conn->last_alive);
		LOGINFO("Sent %s (%u bytes) to peer %d", cmd, plen, conn->peer);
	}
}

/* Safe way to read a peer pointer while the array may be resized */
static p2p_conn_t *get_peer(ckpool_t *ckp, int peer)
{
	p2p_conn_t *conn = NULL;

	ck_rlock(&peerlock);
	if (likely(peer < ckp->p2purls))
		conn = ckp->p2pconn[peer];
	ck_runlock(&peerlock);

	return conn;
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
		LOGNOTICE("Magic mismatch");
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
			LOGNOTICE("Checksum fail on %s (empty)", cmd);
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
		LOGNOTICE("Checksum fail on %s", cmd);
		dealloc(*payload);
		*payload = NULL;
		return false;
	}

	tv_time(&conn->last_alive);
	return true;
}

/* Build and send VERSION message (used by both outgoing and incoming handshakes).
 * Advertises CKP2P_LISTEN_PORT in addr_from. */
static void send_version(p2p_conn_t *conn, int remote_port)
{
	uchar version_payload[97] = {};
	int off = 0;
	uint32_t nversion = 70016;
	uint32_t nversion_le = htole32(nversion);
	memcpy(version_payload + off, &nversion_le, sizeof(nversion_le));
	off += sizeof(nversion_le);

	uint64_t services = 9ULL;
	uint64_t services_le = htole64(services);
	memcpy(version_payload + off, &services_le, sizeof(services_le));
	off += sizeof(services_le);

	uint64_t ntime = (uint64_t)time(NULL);
	uint64_t ntime_le = htole64(ntime);
	memcpy(version_payload + off, &ntime_le, sizeof(ntime_le));
	off += sizeof(ntime_le);

	/* addr_recv (remote peer) */
	uint64_t recv_services_le = htole64(services);
	memcpy(version_payload + off, &recv_services_le, sizeof(recv_services_le));
	off += sizeof(recv_services_le);
	uchar recv_ip[16] = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xff,0xff,0x7f,0x00,0x00,0x01};
	memcpy(version_payload + off, recv_ip, 16);
	off += 16;
	uint16_t recv_port_be = htons(remote_port);
	memcpy(version_payload + off, &recv_port_be, sizeof(recv_port_be));
	off += sizeof(recv_port_be);

	/* addr_from: advertise ourselves as listening on CKP2P_LISTEN_PORT */
	uint64_t from_services_le = htole64(services);
	memcpy(version_payload + off, &from_services_le, sizeof(from_services_le));
	off += sizeof(from_services_le);
	memset(version_payload + off, 0, 16);
	off += 16;
	uint16_t from_port_be = htons(CKP2P_LISTEN_PORT);
	memcpy(version_payload + off, &from_port_be, sizeof(from_port_be));
	off += sizeof(from_port_be);

	/* nonce */
	uint64_t nnonce = ((uint64_t)rand() << 32) | rand();
	uint64_t nnonce_le = htole64(nnonce);
	memcpy(version_payload + off, &nnonce_le, sizeof(nnonce_le));
	off += sizeof(nnonce_le);

	const char *ua = "/ckp2p:1.0/";
	uchar ualen = (uchar)strlen(ua);
	version_payload[off++] = ualen;
	memcpy(version_payload + off, ua, ualen);
	off += ualen;

	uint32_t height = 0;
	uint32_t height_le = htole32(height);
	memcpy(version_payload + off, &height_le, sizeof(height_le));
	off += sizeof(height_le);

	version_payload[off++] = 0; /* relay = 0 */

	p2p_send(conn, "version", version_payload, sizeof(version_payload));
}

/* Send self-advertisement via addrv2 (BIP155) so other nodes can discover us.
 * Uses getsockname() on the live socket to automatically get our public IPv4 address. */
static void send_self_addrv2(p2p_conn_t *conn)
{
	struct sockaddr_in local;
	socklen_t len = sizeof(local);

	if (externalip)
		local.sin_addr.s_addr = externalip;
	else if (getsockname(conn->sock, (struct sockaddr *)&local, &len) < 0) {
		LOGDEBUG("getsockname failed for self-advertisement");
		return;
	}

	/* Build addrv2 payload with exactly 1 address (our own) */
	uchar payload[64];
	uint32_t pos = 0;

	/* count = 1 (varint) */
	payload[pos++] = 1;

	/* time (uint32_t, current time) */
	uint32_t now = (uint32_t)time(NULL);
	uint32_t now_le = htole32(now);
	memcpy(payload + pos, &now_le, 4);
	pos += 4;

	/* services (varint = 9) */
	payload[pos++] = 9;

	/* network ID = 1 (IPv4) */
	payload[pos++] = 1;

	/* address length (varint = 4) */
	payload[pos++] = 4;

	/* IPv4 address (network byte order) */
	memcpy(payload + pos, &local.sin_addr.s_addr, 4);
	pos += 4;

	/* port (big-endian, our listening port) */
	uint16_t port_be = htons(CKP2P_LISTEN_PORT);
	memcpy(payload + pos, &port_be, 2);
	pos += 2;

	p2p_send(conn, "addrv2", payload, pos);
	LOGINFO("Sent self addrv2 advertisement to peer (%s:%d)", conn->host, conn->port);
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

/* Perform under wlock peerlock */
static inline void _activate_conn(p2p_conn_t *conn)
{
	if (!conn->active) {
		conn->active = true;
		active_conns++;
	}
}

static void activate_conn(p2p_conn_t *conn)
{
	ck_wlock(&peerlock);
	_activate_conn(conn);
	ck_wunlock(&peerlock);
}

static void deactivate_conn(p2p_conn_t *conn)
{
	ck_wlock(&peerlock);
	if (conn->active) {
		conn->active = false;
		active_conns--;
	}
	ck_wunlock(&peerlock);
}

/* Disconnect after sending any block response to prevent being
 * asked for more info we don't have */
static void disconnect_conn(p2p_conn_t *conn)
{
	LOGDEBUG("Disconnecting peer %d", conn->peer);
	close(conn->sock);
	conn->sock = -1;
	conn->handshake_done = false;
	deactivate_conn(conn);
}

static void evict_peer(p2p_conn_t *conn)
{
	ck_wlock(&peerlock);
	if (conn->evicted) {
		ck_wunlock(&peerlock);
		return;
	}
	HASH_DEL(p2ppeers, conn->p2ppeer);
	dealloc(conn->p2ppeer);
	conn->evicted = true;
	ck_wunlock(&peerlock);

	disconnect_conn(conn);
	/* NOTE possible leak if contains ->cmpct_payload here but is very
	 * unlikely */
	total_conns--;
}

static void evict_peerno(ckpool_t *ckp, int peer)
{
	p2p_conn_t *conn = get_peer(ckp, peer);

	if (likely(conn))
		evict_peer(conn);
}

/* Done under wlock peerlock for multiples */
static void _add_connector(p2p_conn_t *conn)
{
	wakelist_t *waker = NULL;
	bool new = false;

	HASH_FIND_INT(connector_wakes, &conn->peer, waker);
	if (!waker) {
		waker = ckalloc(sizeof(wakelist_t));
		waker->peer = conn->peer;
		HASH_ADD_INT(connector_wakes, peer, waker);
		new = true;
	}

	if (new)
		ckmsgq_add(p2p_connectors, conn);
}

static void add_connector(p2p_conn_t *conn)
{
	wakelist_t *waker = NULL;
	bool new = false;

	ck_wlock(&peerlock);
	HASH_FIND_INT(connector_wakes, &conn->peer, waker);
	if (!waker) {
		waker = ckalloc(sizeof(wakelist_t));
		waker->peer = conn->peer;
		HASH_ADD_INT(connector_wakes, peer, waker);
		new = true;
	}
	ck_wunlock(&peerlock);

	if (new)
		ckmsgq_add(p2p_connectors, conn);
}

static void add_reader(p2p_conn_t *conn)
{
	wakelist_t *waker = NULL;
	bool new = false;

	ck_wlock(&peerlock);
	HASH_FIND_INT(reader_wakes, &conn->peer, waker);
	if (!waker) {
		waker = ckalloc(sizeof(wakelist_t));
		waker->peer = conn->peer;
		HASH_ADD_INT(reader_wakes, peer, waker);
		new = true;
	}
	ck_wunlock(&peerlock);

	if (new)
		ckmsgq_add(p2p_readers, conn);
}

static void del_connector(p2p_conn_t *conn)
{
	wakelist_t *waker = NULL;

	ck_wlock(&peerlock);
	HASH_FIND_INT(connector_wakes, &conn->peer, waker);
	if (waker)
		HASH_DEL(connector_wakes, waker);
	ck_wunlock(&peerlock);

	dealloc(waker);
}

static void del_reader(p2p_conn_t *conn)
{
	wakelist_t *waker = NULL;

	ck_wlock(&peerlock);
	HASH_FIND_INT(reader_wakes, &conn->peer, waker);
	if (waker)
		HASH_DEL(reader_wakes, waker);
	ck_wunlock(&peerlock);

	dealloc(waker);
}

static int connectors_woken(void)
{
	int ret;

	ck_rlock(&peerlock);
	ret = HASH_COUNT(connector_wakes);
	ck_runlock(&peerlock);

	return ret;
}

static void handle_getdata(p2p_conn_t *conn, uchar *payload, uint32_t plen)
{
	uint32_t pos = 0;
	int64_t count = parse_varint(payload, plen, &pos);
	bool responded = false;

	if (count < 0 || count > 500) { // basic sanity
		dealloc(payload);
		return;
	}
	for (int64_t i = 0; i < count; i++) {
		uint32_t type_le, type;
		uchar hash[32];

		if (pos + 36 > plen)
			break;
		memcpy(&type_le, payload + pos, 4);
		type = le32toh(type_le);
		pos += 4;
		memcpy(hash, payload + pos, 32);
		pos += 32;

		if (type == MSG_CMPCT_BLOCK) {
			ck_rlock(&conn->block_lock);
			if (conn->has_block && !memcmp(conn->blockhash, hash, 32)) {
				p2p_send(conn, "cmpctblock", conn->cmpct_payload, conn->cmpct_len);
				responded = true;
			} else
				LOGINFO("Peer %d requested cmpctblock we don't have", conn->peer);
			ck_runlock(&conn->block_lock);
		} else {
			LOGINFO("Peer %d requested full block (getdata) - cannot serve",
				conn->peer);
		}

		if (!responded) {
			disconnect_conn(conn);
			add_connector(conn);
		}
	}
	dealloc(payload);
}

static void handle_getblocktxn(p2p_conn_t *conn, uchar *payload, uint32_t plen)
{
	if (plen < 32) {
		dealloc(payload);
		return;
	}

	LOGINFO("Peer %d requested getblocktxn - cannot serve", conn->peer);

	/* Disconnect immediately so bitcoind doesn't wait the full timeout */
	disconnect_conn(conn);
	add_connector(conn);

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

static void display_newblock(uchar *blockhash)
{
	char fliphash[32], showhash[68];

	bswap_256(fliphash, blockhash);
	__bin2hex(showhash, fliphash, 32);
	LOGWARNING("New block hash detected: %s", showhash);
}

/* Bitcoin target-from-bits (little-endian target array, index 0 = LSB) */
static void target_from_bits(uchar *target, uint32_t bits)
{
	memset(target, 0, 32);

	int nsize = (bits >> 24) & 0xff;
	uint32_t mant = bits & 0x007fffff;

	if (nsize <= 3) {
		mant >>= 8 * (3 - nsize);
		target[3 - nsize] = mant & 0xff;
	} else {
		target[nsize - 3] = (mant >> 16) & 0xff;
		target[nsize - 2] = (mant >> 8) & 0xff;
		target[nsize - 1] = mant & 0xff;
	}
}

/* Returns true if block hash meets the target (both arrays little-endian) */
static bool hash_meets_target(const uchar *hash, uint32_t bits)
{
	uchar target[32];
	target_from_bits(target, bits);

	/* Compare from MSB (index 31) to LSB (index 0) */
	for (int i = 31; i >= 0; i--) {
		if (hash[i] < target[i]) return true;
		if (hash[i] > target[i]) return false;
	}
	return true;   /* exact match is valid */
}

static int blockcmp(blocklist_t *a, uchar *b)
{
	return memcmp(a->hash, b, 32);
}

/* Function for testing cmpctblock validity by echoing back any received */
static void handle_cmpctblock(ckpool_t *ckp, uchar *payload, uint32_t plen, int source)
{
	uint64_t shortid_nonce_le, shortid_nonce;
	bool new_block = false;
	uint32_t block_bits;

	if (plen < 88) {
		dealloc(payload);
		return;
	}
	uchar header[80];
	memcpy(header, payload, 80);
	memcpy(&block_bits, header + 72, 4);
	block_bits = le32toh(block_bits);

	/* Trust priority peers implicitly; other peers only if diff is higher */
	if (block_bits != current_bits) {
		if (current_bits > block_bits || source < ckp->prioclients) {
			LOGWARNING("Current bits set to 0x%08x (from peer %d)", block_bits, source);

			ck_wlock(&curblock.lock);
			current_bits = block_bits;
			ck_wunlock(&curblock.lock);
		}
	}

	uchar h1[32], blockhash[32];
	sha256(header, 80, h1);
	sha256(h1, 32, blockhash);

	if (!hash_meets_target(blockhash, current_bits)) {
		LOGWARNING("Compact block from peer %d does not meet current difficulty target (0x%08x) - dropping",
			   source, current_bits);
		dealloc(payload);
		if (likely(source))
			evict_peerno(ckp, source);
		else
			LOGERR("Peer 0 compact block doesn't meet target!");
		return;
	}

	memcpy(&shortid_nonce_le, payload + 80, 8);
	shortid_nonce = le64toh(shortid_nonce_le);

	ck_wlock(&curblock.lock);
	if (memcmp(curblock.hash, blockhash, 32)) {
		blocklist_t *block;

		/* Check this hash hasn't been seen in the last 100 blocks as
		 * compact blocks are often repeated, to avoid relaying the
		 * same block again */
		DL_SEARCH(blockhashes, block, blockhash, blockcmp);
		if (!block) {
			int count;

			block = ckalloc(sizeof(blocklist_t));

			memcpy(block->hash, blockhash, 32);
			DL_APPEND(blockhashes, block);
			DL_COUNT(blockhashes, block, count);
			LOGDEBUG("Block count %d", count);
			if (count > 100) {
				block = blockhashes;
				DL_DELETE(blockhashes, block);
				free(block);
			}
			memcpy(curblock.hash, blockhash, 32);
			new_block = true;
		} else
			LOGDEBUG("Block already exists");
	}
	ck_wunlock(&curblock.lock);

	if (new_block) {
		display_newblock(blockhash);
		relay_compact_block(ckp, blockhash, payload, plen, shortid_nonce, source);
		/* payload is stolen and released by relay_compact_block */
	} else
		dealloc(payload);
}

static bool p2p_connect_socket(p2p_conn_t *conn)
{
	conn->sock = connect_socket(conn->host, conn->charport);
	if (conn->sock < 0) {
		LOGINFO("connect_socket failed in p2p_connect_socket to peer %d", conn->peer);
		return false;
	}
	LOGNOTICE("ckp2p connected to peer %d, %s:%d (%s)", conn->peer, conn->host,
		  conn->port, conn->netname);

	return true;
}

static bool do_handshake(p2p_conn_t *conn, int port)
{
	char cmd[13];
	uchar *payload;
	uint32_t plen;

	send_version(conn, port);

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
	LOGNOTICE("P2P handshake complete with peer %d on %s - ready for compact blocks",
		  conn->peer, conn->netname);

	/* Advertise ourselves to the network */
	send_self_addrv2(conn);

	return true;
}

/* called while holding peerlock */
static bool _dup_peer(ckpool_t *ckp, const char *host, int port)
{
	peerlist_t *p2ppeer = NULL;
	bool ret = false;
	char url[288];

	sprintf(url, "%s:%d", host, port);
	HASH_FIND_STR(p2ppeers, url, p2ppeer);
	if (p2ppeer)
		ret = true;
	return ret;
}

static bool dup_peer(ckpool_t *ckp, const char *host, int port)
{
	bool ret;

	ck_rlock(&peerlock);
	ret = _dup_peer(ckp, host, port);
	ck_runlock(&peerlock);

	return ret;
}

/* Server-side handshake for incoming connections (peer sends VERSION first) */
static bool do_incoming_handshake(p2p_conn_t *conn)
{
	char cmd[13];
	uchar *payload = NULL;
	uint32_t plen;

	/* Wait for VERSION from the incoming peer */
	LOGINFO("Waiting for VERSION from incoming peer...");
	while (42) {
		if (!p2p_recv(conn, cmd, &payload, &plen))
			return false;
		LOGINFO("Received %s (%u bytes)", cmd, plen);
		if (!strcmp(cmd, "version")) {
			LOGINFO("Received VERSION from incoming peer");

			/* Try to extract the peer's real listening address/port from addr_from */
			char adv_host[INET_ADDRSTRLEN] = {0};
			int adv_port = 0;

			if (parse_version_addr_from(payload, plen, adv_host, &adv_port)) {
				LOGNOTICE("Peer advertised listening address %s:%d - updating reconnection info",
					  adv_host, adv_port);
				strncpy(conn->host, adv_host, sizeof(conn->host) - 1);
			}
			if (!adv_port)
				adv_port = P2P_LISTEN_PORT; /* Set to default if we don't get it */
			conn->port = adv_port;
			snprintf(conn->charport, sizeof(conn->charport), "%d", adv_port);
			if (dup_peer(conn->ckp, conn->host, conn->port)) {
				LOGNOTICE("Duplicate incoming peer %s:%s, will not reconnect if dropped", conn->host, conn->charport);
				conn->incoming_only = true;
			}

			if (payload)
				dealloc(payload);
			break;
		}
		if (payload)
			dealloc(payload);
	}

	/* Send our VERSION (advertises CKP2P_LISTEN_PORT) */
	send_version(conn, conn->port);

	/* Negotiation messages (same as outgoing) */
	p2p_send(conn, "wtxidrelay", NULL, 0);
	p2p_send(conn, "sendaddrv2", NULL, 0);

	uchar sc[9] = {0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}; /* high_bw=1, ver=2 */
	p2p_send(conn, "sendcmpct", sc, 9);

	p2p_send(conn, "verack", NULL, 0);

	/* Wait for VERACK */
	LOGINFO("Waiting for VERACK from incoming peer...");
	while (42) {
		if (!p2p_recv(conn, cmd, &payload, &plen))
			return false;
		LOGINFO("Received %s (%u bytes)", cmd, plen);
		if (!strcmp(cmd, "verack")) {
			LOGINFO("Received VERACK - handshake complete for incoming peer");
			if (payload) dealloc(payload);
			break;
		}
		if (payload)
			dealloc(payload);
	}

	conn->handshake_done = true;
	LOGNOTICE("P2P incoming handshake complete with peer on %s - ready for compact blocks",
		  conn->netname);

	/* Advertise ourselves to the network */
	send_self_addrv2(conn);

	return true;
}

static void add_conn_epoll(p2p_conn_t *conn)
{
	if (conn->sock < 0 || conn->evicted)
		return;

	struct epoll_event event = {
		.events = EPOLLIN | EPOLLRDHUP | EPOLLERR | EPOLLONESHOT,
		.data.u64 = (uint64_t)conn->peer,
	};

	if (epoll_ctl(reader_epfd, EPOLL_CTL_MOD, conn->sock, &event) < 0) {
		if (errno == ENOENT) {
			/* New fd not yet registered (fresh connect) - use ADD */
			if (epoll_ctl(reader_epfd, EPOLL_CTL_ADD, conn->sock, &event) < 0)
				LOGDEBUG("epoll_ctl ADD failed for peer %d (fd %d): %s",
					 conn->peer, conn->sock, strerror(errno));
		} else {
			LOGDEBUG("epoll_ctl MOD failed for peer %d (fd %d): %s",
				 conn->peer, conn->sock, strerror(errno));
		}
	}
}

static void *add_peer(void *arg)
{
	p2p_conn_t *conn = arg;
	ckpool_t *ckp = conn->ckp;

	pthread_detach(pthread_self());
	rename_proc("ckp2pap");

	if (!p2p_connect_socket(conn) || !do_handshake(conn, conn->port)) {
		LOGINFO("No immediate connection to %s:%d, dropping", conn->host,
			conn->port);
		dealloc(conn);
		goto out;
	}

	ck_wlock(&peerlock);
	/* Do another check for duplicates under lock */
	if (unlikely(_dup_peer(ckp, conn->host, conn->port))) {
		ck_wunlock(&peerlock);
		LOGINFO("Skipping duplicate peer %s:%d", conn->host, conn->port);
		disconnect_conn(conn);
		dealloc(conn);
		goto out;
	}

	/* Dynamically grow the peer lists (p2purl, p2pcs, p2pconn) */
	int old = ckp->p2purls;

	/* p2purl */
	char **old_p2purl = ckp->p2purl;
	ckp->p2purl = ckalloc(sizeof(char *) * (old + 1));
	if (old > 0)
		memcpy(ckp->p2purl, old_p2purl, sizeof(char *) * old);
	char *new_url = ckalloc(strlen(conn->host) + strlen(conn->charport) + 2);
	sprintf(new_url, "%s:%s", conn->host, conn->charport);
	ckp->p2purl[old] = new_url;
	if (old_p2purl) dealloc(old_p2purl);

	/* p2pcs (for API consistency) */
	connsock_t **old_p2pcs = ckp->p2pcs;
	ckp->p2pcs = ckalloc(sizeof(connsock_t *) * (old + 1));
	if (old > 0)
		memcpy(ckp->p2pcs, old_p2pcs, sizeof(connsock_t *) * old);
	ckp->p2pcs[old] = NULL;
	if (old_p2pcs) dealloc(old_p2pcs);

	/* p2pconn */
	p2p_conn_t **old_p2pconn = ckp->p2pconn;
	ckp->p2pconn = ckalloc(sizeof(p2p_conn_t *) * (old + 1));
	if (old > 0)
		memcpy(ckp->p2pconn, old_p2pconn, sizeof(p2p_conn_t *) * old);
	ckp->p2pconn[old] = conn;
	if (old_p2pconn) dealloc(old_p2pconn);

	conn->peer = old;
	ckp->p2purls = old + 1;
	total_conns++;
	_activate_conn(conn);

	peerlist_t *p2ppeer = conn->p2ppeer = ckalloc(sizeof(peerlist_t));
	p2ppeer->conn = conn;
	sprintf(p2ppeer->url, "%s:%s", conn->host, conn->charport);
	HASH_ADD_STR(p2ppeers, url, conn->p2ppeer);
	ck_wunlock(&peerlock);

	LOGWARNING("Added whisper peer %s:%d", conn->host, conn->port);
	add_conn_epoll(conn);
out:
	return NULL;
}

static void add_peer_async(ckpool_t *ckp, const char *host, int port)
{
	pthread_t pthread;
	p2p_conn_t *conn;

	LOGINFO("New addrv2: %s:%d", host, port);
	if (!finished_init)
		return;

	conn = ckzalloc(sizeof(*conn));
	conn->ckp = ckp;
	cklock_init(&conn->block_lock);
	conn->cmpct_payload = NULL;
	conn->has_block = false;
	conn->sock = -1;
	strncpy(conn->host, host, sizeof(conn->host) - 1);
	snprintf(conn->charport, sizeof(conn->charport), "%d", port);
	conn->port = port;
	memcpy(conn->magic, netdefs[0].magic, 4);
	memcpy(conn->genesis, netdefs[0].genesis, 32);
	conn->netname = netdefs[0].name;
	conn->peer = -1;

	tv_time(&conn->last_alive);

	create_pthread(&pthread, add_peer, conn);
}

static inline bool client_watermarks(ckpool_t *ckp)
{
	bool ret = true;

	if (total_conns >= ckp->maxclients * 4 / 3)
		goto out;
	if (active_conns >= ckp->maxclients)
		goto out;
	ret = false;
out:
	return ret;
}

static bool pause_clients(ckpool_t *ckp)
{
	bool ret = true;

	if (client_watermarks(ckp))
		goto out;
	if (connectors_woken() >= num_threads)
		goto out;
	ret = false;
out:
	return ret;
}

/* Parse an ADDRV2 message and extract/log all host:port pairs.
 * Supports IPv4 (netid=1) and IPv6 (netid=2). */
static void parse_addrv2(ckpool_t *ckp, uchar *data, uint32_t dlen)
{
	uint32_t pos = 0;
	int i, count;

	if (pause_clients(ckp)) {
		LOGDEBUG("Max client limit reached, not adding more p2p clients");
		goto out;
	}

	count = parse_varint(data, dlen, &pos);
	if (count < 0 || count > 1000) {   /* sanity limit */
		LOGINFO("Invalid or oversized addrv2 count (%d)", count);
		goto out;
	}

	if (count == 0) {
		LOGDEBUG("Received empty addrv2");
		goto out;
	}

	LOGINFO("Received addrv2 with %d address(es)", count);

	for (i = 0; i < count; i++) {
		if (pos + 4 > dlen) break;               /* timestamp */
		pos += 4;                                /* skip timestamp (uint32) */

		int64_t services = parse_varint(data, dlen, &pos);
		if (services < 0) break;

		int64_t netid = parse_varint(data, dlen, &pos);
		if (netid < 0) break;

		int64_t addrlen = parse_varint(data, dlen, &pos);
		if (addrlen < 0 || pos + addrlen + 2 > dlen) break;

		char host[INET6_ADDRSTRLEN] = {0};
		uint16_t port = 0;

		if (netid == 1 && addrlen == 4) {            /* IPv4 */
			struct in_addr ip;
			memcpy(&ip.s_addr, data + pos, 4);
			inet_ntop(AF_INET, &ip, host, sizeof(host));
			pos += 4;
		} else if (netid == 2 && addrlen == 16) {    /* IPv6 */
			struct in6_addr ip6;
			memcpy(&ip6, data + pos, 16);
			inet_ntop(AF_INET6, &ip6, host, sizeof(host));
			pos += 16;
		} else {
			/* Unknown network type or Tor/I2P/etc. – skip */
			pos += addrlen;
			goto next;
		}

		/* Port is always big-endian (network order) */
		uint16_t port_be;
		memcpy(&port_be, data + pos, 2);
		port = ntohs(port_be);
		pos += 2;

		if (port == 0)
			port = 8333;   /* default Bitcoin port if not specified */

		if (!dup_peer(ckp, host, port))
			add_peer_async(ckp, host, port);
		else
			LOGINFO("Dup addrv2: %s:%d", host, port);

	next:
		continue;
	}
out:
	dealloc(data);
}

static void *p2p_receiver(void *arg)
{
	ckpool_t *ckp = arg;
	struct epoll_event event;

	rename_proc("p2preceiver");
	pthread_detach(pthread_self());

	while (42) {
		p2p_conn_t *conn;
		int p2purls, ret;
		uint64_t idx;

		ret = epoll_wait(reader_epfd, &event, 1, 100);
		if (unlikely(ret < 0)) {
			if (errno != EINTR)
				LOGERR("epoll_wait failed: %s", strerror(errno));
			continue;
		}
		if (ret == 0)   /* timeout */
			continue;

		idx = event.data.u64;

		ck_rlock(&peerlock);
		p2purls = ckp->p2purls;
		ck_runlock(&peerlock);

		if (unlikely(idx >= (uint64_t)p2purls)) {
			LOGINFO("invalid peer index %"PRId64, idx);
			continue;
		}

		conn = get_peer(ckp, idx);
		if (unlikely(!conn || conn->evicted))
			continue;

		if (event.events & EPOLLIN)
			add_reader(conn);
		else
			add_connector(conn);
	}
	return NULL;
}

static void p2p_connector(ckpool_t __maybe_unused *ckp, p2p_conn_t *conn)
{
	if (unlikely(conn->evicted))
		goto out;

	if (conn->sock < 0) {
		if (conn->incoming_only) {
			evict_peer(conn);
			goto out;
		}

		if (p2p_connect_socket(conn)) {
			if (!do_handshake(conn, conn->port)) {
				close(conn->sock);
				conn->sock = -1;
			}
		}
		if (conn->sock < 0)
			goto out;
	}

	activate_conn(conn);

	add_reader(conn);
out:
	del_connector(conn);
	return;
}

static void p2p_reader(ckpool_t *ckp, p2p_conn_t *conn)
{
	uchar *payload = NULL;
	struct pollfd fdpoll = {};
	uint32_t plen;
	char cmd[13];
	int ret;

	if (unlikely(conn->evicted))
		goto out;

	if (conn->sock < 0 || !conn->handshake_done) {
		deactivate_conn(conn);
		add_connector(conn);
		goto out;
	}

	activate_conn(conn);

	/* Sanity check we haven't been woken up without anything to read */
	fdpoll.fd = conn->sock;
	fdpoll.events = POLLIN;
	ret = poll(&fdpoll, 1, 0);
	if (!ret) /* Nothing ready to read */
		goto rearm;

	if (!p2p_recv(conn, cmd, &payload, &plen)) {
		LOGINFO("P2P recv failed for peer %d - disconnecting", conn->peer);
		disconnect_conn(conn);
		add_connector(conn);
		goto out;
	}

	// Log all received messages with descriptive type, even if ignoring
	if (!strcmp(cmd, "version")) {
		LOGINFO("Received VERSION (%u bytes) - handling for handshake", plen);
	} else if (!strcmp(cmd, "verack")) {
		LOGINFO("Received VERACK (%u bytes) - handling for handshake", plen);
	} else if (!strcmp(cmd, "ping")) {
		LOGINFO("Received PING (%u bytes) - replying with PONG", plen);
		handle_ping(conn, payload, plen);
		goto rearm; // Skip dealloc since handler does it
	} else if (!strcmp(cmd, "pong")) {
		LOGDEBUG("Received PONG (%u bytes) - ignoring (keep-alive response)", plen);
	} else if (!strcmp(cmd, "sendcmpct")) {
		LOGINFO("Received SENDCMPCT (%u bytes) - handling compact block negotiation", plen);
		handle_sendcmpct(conn, payload, plen);
		goto rearm; // Skip dealloc since handler does it
	} else if (!strcmp(cmd, "getdata")) {
		LOGINFO("Received GETDATA (%u bytes) - handling (request for compact block or tx)", plen);
		handle_getdata(conn, payload, plen);
		goto rearm; // Skip dealloc since handler does it
	} else if (!strcmp(cmd, "getblocktxn")) {
		LOGINFO("Received GETBLOCKTXN (%u bytes) - handling (request for block txn)", plen);
		handle_getblocktxn(conn, payload, plen);
		goto rearm; // Skip dealloc since handler does it
	} else if (!strcmp(cmd, "inv")) {
		handle_inv(conn, payload, plen);
		goto rearm;
	} else if (!strcmp(cmd, "headers")) {
		LOGINFO("Received HEADERS (%u bytes) - ignoring", plen);
	} else if (!strcmp(cmd, "cmpctblock")) {
		LOGNOTICE("Received CMPCTBLOCK from peer %d (%u bytes) - handling (resend to all nodes)", conn->peer, plen);
		handle_cmpctblock(ckp, payload, plen, conn->peer);
		goto rearm;
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
		LOGINFO("Received ADDRV2 (%u bytes)", plen);
		parse_addrv2(ckp, payload, plen);
		goto rearm; // Handler deallocates
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

	if (payload)
		dealloc(payload);
rearm:
	del_reader(conn);
	add_conn_epoll(conn);
	return;
out:
	deactivate_conn(conn);
	del_reader(conn);
}

/* Stores a copy of non-evicted outgoing peers every minute to peers.conf */
static void dump_peers(ckpool_t *ckp)
{
	peerlist_t *p2ppeer;
	int count = 0;
	FILE *fp;

	fp = fopen("peers.conf", "we");
	if (unlikely(!fp)) {
		LOGERR("Unable to fopen peers.conf in dump_peers");
		return;
	}
	fprintf(fp, "{\n\"maxclients\" : %d,\n", ckp->maxclients);
	fprintf(fp, "\"prioclients\" : %d,\n", ckp->prioclients);
	fprintf(fp, "\"externalip\" : \"%s\",\n", ckp->externalip);
	fprintf(fp, "\"p2purl\" : [");

	ck_rlock(&peerlock);
	for (p2ppeer = p2ppeers; p2ppeer!= NULL; p2ppeer = p2ppeer->hh.next) {
		p2p_conn_t *conn = p2ppeer->conn;
		struct in6_addr addr;

		if (conn->incoming_only)
			continue;

		/* check if host is ipv6 */
		if (inet_pton(AF_INET6, conn->host, &addr) == 1)
			fprintf(fp, "%s\n\t\"[%s]:%d\"", count++ ? "," : "", conn->host, conn->port);
		else
			fprintf(fp, "%s\n\t\"%s:%d\"", count++ ? "," : "", conn->host, conn->port);
	}
	ck_runlock(&peerlock);

	fprintf(fp, "\n]\n}\n");
	fclose(fp);
	LOGINFO("Stored %d peers in peers.conf", count);
}

static void *p2p_keepalive(void *arg)
{
	tv_t last_ping;
	ckpool_t *ckp = arg;
	ts_t last_update;

	tv_time(&last_ping);
	cksleep_prepare_r(&last_update);

	pthread_detach(pthread_self());
	rename_proc("ckp2pk");

	while (42) {
		uint64_t nonce, nonce_le;
		bool ping = false;
		int p2purls, i;
		tv_t now;

		ck_rlock(&peerlock);
		p2purls = ckp->p2purls;
		ck_runlock(&peerlock);
#ifdef CKP2P
		printf("Peers:%d, Connections:%d, Active:%d            \r", p2purls,
		       total_conns, active_conns);
		fflush(NULL);
#endif
		/* Use re-entrant function since it can take a while to get
		 * back here with many peers */
		cksleep_ms_r(&last_update, KEEPALIVE_INTERVAL * 1000);
		cksleep_prepare_r(&last_update);
		ts_to_tv(&now, &last_update);

		if (tvdiff(&now, &last_ping) > PING_INTERVAL) {
			copy_tv(&last_ping, &now);
			ping = true;
			dump_peers(ckp);
		}

		for (i = 0; i < p2purls ; i++) {
			p2p_conn_t *conn = get_peer(ckp, i);

			if (unlikely(!conn))
				continue;
			if (conn->evicted)
				continue;
			if (!conn->handshake_done || conn->sock < 0) {
				int unresponsive = 0, timeout = EVICT_TIMEOUT;

				if (conn->incoming_only) {
					evict_peer(conn);
					continue;
				}
				/* Never evict priority clients */
				if (i >= ckp->prioclients)
					unresponsive = tvdiff(&now, &conn->last_alive);
				if (client_watermarks(ckp))
					timeout = FAST_EVICT;
				if (unresponsive >= timeout) {
					LOGWARNING("Dropping peer %d unresponsive for %d seconds",
						   conn->peer, unresponsive);
					evict_peer(conn);
					continue;
				}
				/* Tell p2p_connectors to try reconnecting */
				add_connector(conn);
				continue;
			}

			if (!ping)
				continue;
			nonce = ((uint64_t)rand() << 32) | rand();
			nonce_le = htole64(nonce);
			p2p_send(conn, "ping", (uchar *)&nonce_le, 8);
		}
	}

	return NULL;
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
	char fliphash[32], hex[68];
	ckpool_t *ckp = cbt->ckp;
	int i, submitted = 0;
	int p2purls;

	pthread_detach(pthread_self());

	ck_rlock(&peerlock);
	p2purls = ckp->p2purls;
	ck_runlock(&peerlock);

	for (i = 0; i < p2purls; i++) {
		p2p_conn_t *conn;

		if (i == cbt->source) {
			LOGDEBUG("Skipping relaying compact block to source node %d", i);
			continue;
		}

		conn = get_peer(ckp, i);
		if (unlikely(!conn)) {
			LOGDEBUG("Skipping relaying compact block to uninitialised node %d", i);
			continue;
		}
		if (conn->evicted) {
			LOGDEBUG("Skipping relaying compact block to evicted node %d", i);
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
		/* Disconnect all priority peers to avoid inducing latency at
		 * their end in case they ask for more information from ckp2p.*/
		if (i < ckp->prioclients) {
			disconnect_conn(conn);
			add_connector(conn);
		}

		submitted++;
	}

	bswap_256(fliphash, cbt->blockhash);
	__bin2hex(hex, fliphash, 32);
	if (submitted)
		LOGNOTICE("Submitted %d compact block%s %s", submitted, submitted > 1 ? "s" : "", hex);
	free(cbt->cmpct_payload);
	free(cbt);

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
	int port, i;

	conn->ckp = ckp;
	cklock_init(&conn->block_lock);
	conn->peer = source;
	conn->cmpct_payload = NULL;
	conn->has_block = false;
	conn->handshake_done = false;
	conn->sock = -1;
	strncpy(conn->host, host, sizeof(conn->host) - 1);
	strncpy(conn->charport, charport, sizeof(conn->charport) - 1);
	sscanf(charport, "%d", &port);
	conn->port = port;
	memset(conn->magic, 0, 4); // unset

	/* Set initial attempted connection time */
	tv_time(&conn->last_alive);

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

	LOGWARNING("ckp2p set up config peer %d - %s:%s", source, host, charport);

	return conn;
}

/* Listener socket creator (all interfaces) */
static int create_p2p_listener(void)
{
	int sock;
	struct sockaddr_in sin;

	sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock < 0) {
		LOGEMERG("Failed to create ckp2p listener socket: %s", strerror(errno));
		return -1;
	}

	int opt = 1;
	setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = INADDR_ANY;
	sin.sin_port = htons(externalport);

	if (bind(sock, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
		LOGEMERG("Failed to bind ckp2p listener port %d: %s", externalport, strerror(errno));
		close(sock);
		return -1;
	}

	if (listen(sock, 32) < 0) {
		LOGEMERG("Failed to listen on ckp2p port %d: %s", externalport, strerror(errno));
		close(sock);
		return -1;
	}

	LOGNOTICE("ckp2p listening on 0.0.0.0:%d for incoming P2P connections", externalport);
	return sock;
}

/* Acceptor thread – accepts incoming connections, runs full handshake,
 * adds them to the p2purl / p2pconn lists, and spawns reader/keepalive threads
 * exactly like outgoing peers. */
static void *p2p_acceptor(void *arg)
{
	ckpool_t *ckp = arg;

	pthread_detach(pthread_self());
	rename_proc("ckp2pa");

	int listen_sock = create_p2p_listener();
	if (listen_sock < 0)
		return NULL;

	while (42) {
		struct sockaddr_in client_addr;
		socklen_t clen = sizeof(client_addr);
		int newsock;

		while (pause_clients(ckp))
			sleep(KEEPALIVE_INTERVAL);
		newsock = accept(listen_sock, (struct sockaddr *)&client_addr, &clen);
		if (newsock < 0) {
			if (errno != EINTR)
				LOGDEBUG("accept error: %s", strerror(errno));
			continue;
		}

		char host[INET_ADDRSTRLEN];
		inet_ntop(AF_INET, &client_addr.sin_addr, host, sizeof(host));
		int port_num = ntohs(client_addr.sin_port);
		char serv[16];
		snprintf(serv, sizeof(serv), "%d", port_num);

		LOGNOTICE("Incoming ckp2p connection from %s:%d", host, port_num);

		p2p_conn_t *conn = ckzalloc(sizeof(*conn));
		conn->ckp = ckp;
		cklock_init(&conn->block_lock);
		conn->sock = newsock;
		strncpy(conn->host, host, sizeof(conn->host) - 1);
		strncpy(conn->charport, serv, sizeof(conn->charport) - 1);
		conn->port = port_num;
		memset(conn->magic, 0, 4); /* auto-detect */
		memcpy(conn->genesis, netdefs[0].genesis, 32);
		conn->netname = netdefs[0].name;
		conn->cmpct_payload = NULL;
		tv_time(&conn->last_alive);
		conn->peer = -1;

		if (!do_incoming_handshake(conn)) {
			LOGINFO("Incoming handshake failed from %s:%d", host, port_num);
			close(newsock);
			dealloc(conn);
			continue;
		}

		ck_wlock(&peerlock);
		/* Dynamically grow the peer lists (p2purl, p2pcs, p2pconn) */
		int old = ckp->p2purls;

		/* p2purl */
		char **old_p2purl = ckp->p2purl;
		ckp->p2purl = ckalloc(sizeof(char *) * (old + 1));
		if (old > 0)
			memcpy(ckp->p2purl, old_p2purl, sizeof(char *) * old);
		char *new_url = ckalloc(strlen(host) + strlen(serv) + 2);
		sprintf(new_url, "%s:%s", host, serv);
		ckp->p2purl[old] = new_url;
		if (old_p2purl) dealloc(old_p2purl);

		/* p2pcs (for API consistency) */
		connsock_t **old_p2pcs = ckp->p2pcs;
		ckp->p2pcs = ckalloc(sizeof(connsock_t *) * (old + 1));
		if (old > 0)
			memcpy(ckp->p2pcs, old_p2pcs, sizeof(connsock_t *) * old);
		ckp->p2pcs[old] = NULL;
		if (old_p2pcs) dealloc(old_p2pcs);

		/* p2pconn */
		p2p_conn_t **old_p2pconn = ckp->p2pconn;
		ckp->p2pconn = ckalloc(sizeof(p2p_conn_t *) * (old + 1));
		if (old > 0)
			memcpy(ckp->p2pconn, old_p2pconn, sizeof(p2p_conn_t *) * old);
		ckp->p2pconn[old] = conn;
		if (old_p2pconn)
			dealloc(old_p2pconn);

		conn->peer = old;
		ckp->p2purls = old + 1;
		total_conns++;
		_activate_conn(conn);

		peerlist_t *p2ppeer = conn->p2ppeer = ckalloc(sizeof(peerlist_t));
		p2ppeer->conn = conn;
		sprintf(p2ppeer->url, "%s:%s", conn->host, conn->charport);
		HASH_ADD_STR(p2ppeers, url, p2ppeer);
		ck_wunlock(&peerlock);

		add_conn_epoll(conn);
		LOGWARNING("Added incoming peer %d (%s:%d)", old, host, port_num);
	}

	close(listen_sock);
	return NULL;
}

int prepare_ckp2p(ckpool_t *ckp)
{
	pthread_t pthread;
	connsock_t *cs;
	int i, p2purls;

	cklock_init(&curblock.lock);
	cklock_init(&peerlock);

	if (ckp->externalip) {
		connsock_t cslocal = {};
		struct in_addr addr;

		if (!extract_sockaddr(ckp->externalip, &cslocal.url, &cslocal.port)) {
			LOGEMERG("Failed to extract address from externalip %s", ckp->externalip);
			return -1;
		}
		if (inet_aton(cslocal.url, &addr) == 0) {
			LOGEMERG("Failed to parse IP from externalip %s", ckp->externalip);
			free(cslocal.url);
			free(cslocal.port);
			return -1;
		}
		sscanf(cslocal.port, "%d", &externalport);
		if (!externalport)
			externalport = CKP2P_LISTEN_PORT;
		free(cslocal.url);
		free(cslocal.port);
		externalip = addr.s_addr;
	} else {
		externalport = CKP2P_LISTEN_PORT;
		ASPRINTF(&ckp->externalip, "127.0.0.1:%d", externalport);
	}

	if (ckp->p2purls > ckp->maxclients * 4 / 3) {
		ckp->p2purls = ckp->maxclients * 4 / 3;
		LOGWARNING("Limiting peers to %d", ckp->p2purls);
	}
	p2purls = total_conns = ckp->p2purls;
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

	for (i = 0 ; i < p2purls ; i++) {
		cs = ckp->p2pcs[i];
		p2p_conn_t *conn = ckp->p2pconn[i] = ckp2p_connect(ckp, cs->url, cs->port, i);
		peerlist_t *p2ppeer = conn->p2ppeer = ckalloc(sizeof(peerlist_t));
		p2ppeer->conn = conn;
		sprintf(p2ppeer->url, "%s", ckp->p2purl[i]);
		HASH_ADD_STR(p2ppeers, url, p2ppeer);
	}
	LOGWARNING("ckp2p finished attempting bitcoin node connections.");

	num_threads = sysconf(_SC_NPROCESSORS_ONLN);
	p2p_readers = create_ckmsgqs(ckp, "p2pread", &p2p_reader, num_threads);
	p2p_connectors = create_ckmsgqs(ckp, "p2pconnect", &p2p_connector, num_threads);

	reader_epfd = epoll_create1(EPOLL_CLOEXEC);
	if (reader_epfd < 0)
		quit(1, "FATAL: Failed to create epoll in prepare_ckp2p");

	create_pthread(&pthread, p2p_receiver, ckp);
	create_pthread(&pthread, p2p_keepalive, ckp);

	/* Start listener thread for incoming ckp2p connections on port 8335 */
	create_pthread(&pthread, p2p_acceptor, ckp);
	LOGWARNING("ckp2p listener thread started for incoming connections on port %d", externalport);

	ck_wlock(&peerlock);
	for (i = 0; i < p2purls; i++)
		_add_connector(ckp->p2pconn[i]);
	ck_wunlock(&peerlock);

	finished_init = true;

	return 0;
}
