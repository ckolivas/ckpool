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
#define NODE_NETWORK 1ULL

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
	int source;
} blocklist_t;

static blocklist_t *blockhashes;

#define FAST_SOURCES_MAX 512
#define SLOW_SOURCES_MAX (FAST_SOURCES_MAX / 2)

typedef struct {
	uchar hash[32];
	int peers[FAST_SOURCES_MAX];
	int count;
} fastsources_t;

static fastsources_t fastsources;

typedef struct wakelist {
	UT_hash_handle hh;
	int peer;
} wakelist_t;

static wakelist_t *reader_wakes, *connector_wakes;

static peerlist_t *p2ppeers;

typedef struct txn_relay_group {
	blocklist_t *block;
	uchar *payload;
	uint32_t plen;
	tv_t sent;
	int pending;
	bool done;
} txn_relay_group_t;

typedef struct txn_relay {
	int source_peer;
	txn_relay_group_t *group;
	UT_hash_handle hh;
} txn_relay_t;

static txn_relay_group_t *txn_relay_pending;
static txn_relay_t *txn_relays;
static cklock_t txn_relay_lock;

typedef struct peer0_tx {
	struct peer0_tx *next, *prev;
	uchar *data;
	uint32_t len;
} peer0_tx_t;

static peer0_tx_t *pending_peer0_txs;
static cklock_t pending_peer0_tx_lock;
static bool startup_bits_pending;

#define TXN_RELAY_TIMEOUT_MS 10000
#define TXN_RELAY_POLL_MS 50
#define BLOCKS_FILE "blocks.txt"

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

/* Return true if a VERSION payload indicates a blocksonly peer. */
static bool version_is_blocksonly(const uchar *payload, uint32_t plen)
{
	uint32_t version;
	uint64_t services;
	bool blocksonly;

	if (plen < 12)
		return false;

	memcpy(&version, payload, 4);
	version = le32toh(version);

	memcpy(&services, payload + 4, 8);
	services = le64toh(services);

	blocksonly = !(services & NODE_NETWORK);

	/* fRelay was added in protocol 70001 */
	if (!blocksonly && version >= 70001 && plen >= 81) {
		uint32_t off = 80;

		if (off < plen) {
			uint8_t ualen = payload[off++];

			off += ualen;
			if (off + 5 <= plen) {
				off += 4; /* start_height */
				if (!payload[off])
					blocksonly = true;
			}
		}
	}

	return blocksonly;
}

/* Reject blocksonly peers unless they are configured priority peers. */
static bool reject_blocksonly_peer(p2p_conn_t *conn, const uchar *payload, uint32_t plen)
{
	if (!version_is_blocksonly(payload, plen))
		return false;

	/* peer is -1 for incoming/dynamic peers until added; priority peers are always >= 0 */
	if (conn->peer >= 0 && conn->peer < ckpool.prioclients) {
		LOGNOTICE("Keeping blocksonly priority peer %d", conn->peer);
		return false;
	}

	if (conn->peer >= 0)
		LOGNOTICE("Rejecting blocksonly peer %d", conn->peer);
	else
		LOGNOTICE("Rejecting blocksonly peer %s:%d", conn->host, conn->port);
	return true;
}

static void reset_reconnect(p2p_conn_t *conn)
{
	if (conn->peer < 0 || conn->peer > ckpool.prioclients)
		conn->reconnect = KEEPALIVE_INTERVAL;
}

static void peer_alive(p2p_conn_t *conn)
{
	tv_monotonic(&conn->last_alive);
	reset_reconnect(conn);
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
		peer_alive(conn);
		LOGINFO("Sent %s (%u bytes) to peer %d", cmd, plen, conn->peer);
	}
}

/* Safe way to read a peer pointer while the array may be resized */
static p2p_conn_t *get_peer(int peer)
{
	p2p_conn_t *conn = NULL;

	ck_rlock(&peerlock);
	if (likely(peer < ckpool.p2purls))
		conn = ckpool.p2pconn[peer];
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

	peer_alive(conn);
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

static void evict_peerno(int peer)
{
	p2p_conn_t *conn = get_peer(peer);

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
		if (conn->peer > ckpool.prioclients)
			tv_monotonic(&conn->last_attempt);
	}
	ck_wunlock(&peerlock);

	if (new) {
		if (conn->peer < ckpool.prioclients)
			ckmsgq_add_front(p2p_connectors, conn);
		else
			ckmsgq_add(p2p_connectors, conn);
	}
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

static void add_conn_epoll(p2p_conn_t *conn);
static bool forward_getblocktxn(blocklist_t *block, const uchar *payload, uint32_t plen);
static bool block_has_pending_relay(blocklist_t *block);
static bool peer_sent_block(int peer, const blocklist_t *block);
static void try_extend_txn_relay(int peer, const uchar *hash);
static void expire_txn_relays(tv_t *now);

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
	blocklist_t *block = NULL;

	if (plen < 32) {
		dealloc(payload);
		return;
	}

	if (conn->peer != 0) {
		LOGNOTICE("Peer %d requested getblocktxn - only peer 0 allowed, disconnecting",
			  conn->peer);
		dealloc(payload);
		disconnect_conn(conn);
		add_connector(conn);
		return;
	}

	ck_rlock(&curblock.lock);
	if (blockhashes)
		block = blockhashes->prev;
	ck_runlock(&curblock.lock);

	if (block) {
		LOGWARNING("Peer 0 requested getblocktxn - forwarding txn request");
		if (!forward_getblocktxn(block, payload, plen))
			LOGWARNING("Failed to forward getblocktxn to network peers");
	} else
		LOGINFO("Peer 0 requested getblocktxn but no block available");

	disconnect_conn(conn);
	add_connector(conn);
	dealloc(payload);
}

static void hash_to_hexline(char *hex, const uchar *hash);

static void request_cmpctblock(p2p_conn_t *conn, const uchar *blockhash)
{
	uint32_t req_type = MSG_CMPCT_BLOCK;
	uint32_t req_type_le = htole32(req_type);
	uchar getdata_payload[37];

	getdata_payload[0] = 1;
	memcpy(getdata_payload + 1, &req_type_le, 4);
	memcpy(getdata_payload + 5, blockhash, 32);
	p2p_send(conn, "getdata", getdata_payload, 37);
}

static void try_startup_bits_request(p2p_conn_t *conn)
{
	uchar hash[32];
	char showhash[68];
	bool have_block = false;

	if (!startup_bits_pending || conn->peer != 0 || !conn->handshake_done)
		return;

	ck_rlock(&curblock.lock);
	if (blockhashes) {
		memcpy(hash, curblock.hash, 32);
		have_block = true;
	}
	ck_runlock(&curblock.lock);

	if (!have_block)
		return;

	startup_bits_pending = false;
	request_cmpctblock(conn, hash);
	hash_to_hexline(showhash, hash);
	LOGNOTICE("Requested cmpctblock from peer 0 for %s to set current_bits", showhash);
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
			has_block = true;
			request_cmpctblock(conn, hash);
		}
	}
	if (has_block)
		LOGINFO("Received INV (%u bytes) - requesting cmpctblock for blocks", plen);
	else
		LOGDEBUG("Received INV (%u bytes) - ignoring transaction announcements", plen);
	dealloc(payload);
}

static void relay_compact_block(const uchar *blockhash, uchar *cmpct_payload,
				uint32_t cmpct_len, uint64_t shortid_nonce, int source);

static void display_newblock(uchar *blockhash, int source)
{
	char fliphash[32], showhash[68];

	bswap_256(fliphash, blockhash);
	__bin2hex(showhash, fliphash, 32);
	LOGWARNING("New block hash from peer %d detected: %s", source, showhash);
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

static void hash_to_hexline(char *hex, const uchar *hash)
{
	char fliphash[32];

	bswap_256(fliphash, hash);
	__bin2hex(hex, fliphash, 32);
}

static void hexline_to_hash(uchar *hash, const char *hex)
{
	char fliphash[32];

	hex2bin(fliphash, hex, 32);
	bswap_256(hash, fliphash);
}

static void dump_blocks_txt(void)
{
	FILE *fp;
	blocklist_t *block;
	char hex[68];

	fp = fopen(BLOCKS_FILE, "we");
	if (unlikely(!fp)) {
		LOGERR("Unable to fopen %s for writing", BLOCKS_FILE);
		return;
	}

	ck_rlock(&curblock.lock);
	DL_FOREACH(blockhashes, block) {
		hash_to_hexline(hex, block->hash);
		fprintf(fp, "%s\n", hex);
	}
	ck_runlock(&curblock.lock);
	fclose(fp);
}

static void load_blocks_txt(void)
{
	FILE *fp;
	char buf[128];
	blocklist_t *block, *last = NULL;
	int count = 0;

	fp = fopen(BLOCKS_FILE, "re");
	if (!fp)
		return;

	ck_wlock(&curblock.lock);
	while (fgets(buf, sizeof(buf), fp)) {
		char *nl = strpbrk(buf, "\r\n");
		uchar hash[32];

		if (nl)
			*nl = '\0';
		if (!buf[0])
			continue;
		if (strlen(buf) != 64) {
			LOGWARNING("Invalid %s line: %s", BLOCKS_FILE, buf);
			continue;
		}
		hexline_to_hash(hash, buf);
		block = ckalloc(sizeof(blocklist_t));
		memcpy(block->hash, hash, 32);
		block->source = -1;
		DL_APPEND(blockhashes, block);
		last = block;
		count++;
		if (count > 100) {
			blocklist_t *old = blockhashes;

			if (!block_has_pending_relay(old)) {
				DL_DELETE(blockhashes, old);
				free(old);
				count--;
			}
		}
	}
	if (last) {
		memcpy(curblock.hash, last->hash, 32);
		memcpy(fastsources.hash, last->hash, 32);
		fastsources.count = 0;
	}
	ck_wunlock(&curblock.lock);
	fclose(fp);
	if (count) {
		startup_bits_pending = true;
		LOGWARNING("Loaded %d block hashes from %s", count, BLOCKS_FILE);
	}
}

static bool block_has_pending_relay(blocklist_t *block)
{
	bool ret = false;

	if (!block)
		return false;
	ck_rlock(&txn_relay_lock);
	if (txn_relay_pending && txn_relay_pending->block == block)
		ret = true;
	ck_runlock(&txn_relay_lock);
	return ret;
}

static void add_fast_source(const uchar *hash, int peer)
{
	int i;
	bool added = false;

	ck_wlock(&curblock.lock);
	if (memcmp(fastsources.hash, hash, 32)) {
		memcpy(fastsources.hash, hash, 32);
		fastsources.count = 0;
	}
	for (i = 0; i < fastsources.count; i++) {
		if (fastsources.peers[i] == peer) {
			ck_wunlock(&curblock.lock);
			return;
		}
	}
	if (fastsources.count < FAST_SOURCES_MAX) {
		fastsources.peers[fastsources.count++] = peer;
		added = true;
		LOGDEBUG("Fast source %d added (%d/%d) for current block",
			 peer, fastsources.count, FAST_SOURCES_MAX);
	}
	ck_wunlock(&curblock.lock);

	if (added)
		try_extend_txn_relay(peer, hash);
}

/* Forward a pending getblocktxn to a newly discovered fast source. */
static void try_extend_txn_relay(int peer, const uchar *hash)
{
	txn_relay_group_t *group;
	txn_relay_t *relay, *existing;
	p2p_conn_t *sc;
	uchar *payload;
	uint32_t plen;
	int pending;

	if (!peer)
		return;

	ck_wlock(&txn_relay_lock);
	group = txn_relay_pending;
	if (!group || group->done || !group->payload || !group->block)
		goto out;
	if (memcmp(group->block->hash, hash, 32))
		goto out;
	if (group->pending >= FAST_SOURCES_MAX)
		goto out;
	HASH_FIND_INT(txn_relays, &peer, existing);
	if (existing)
		goto out;

	payload = group->payload;
	plen = group->plen;
	ck_wunlock(&txn_relay_lock);

	sc = get_peer(peer);
	if (unlikely(!sc) || sc->evicted || sc->sock < 0 || !sc->handshake_done)
		return;

	ck_wlock(&txn_relay_lock);
	group = txn_relay_pending;
	if (!group || group->done || !group->payload || !group->block)
		goto out;
	if (memcmp(group->block->hash, hash, 32))
		goto out;
	if (group->pending >= FAST_SOURCES_MAX)
		goto out;
	HASH_FIND_INT(txn_relays, &peer, existing);
	if (existing)
		goto out;

	relay = ckalloc(sizeof(txn_relay_t));
	relay->source_peer = peer;
	relay->group = group;
	HASH_ADD_INT(txn_relays, source_peer, relay);
	group->pending++;
	pending = group->pending;
	ck_wunlock(&txn_relay_lock);

	p2p_send(sc, "getblocktxn", payload, plen);
	LOGWARNING("Extended txn relay to fast source %d (%d/%d)", peer, pending,
		   FAST_SOURCES_MAX);
	return;
out:
	ck_wunlock(&txn_relay_lock);
}

/* Must hold txn_relay_lock */
static void delete_txn_relay_group_locked(txn_relay_group_t *group)
{
	txn_relay_t *relay, *tmp;

	HASH_ITER(hh, txn_relays, relay, tmp) {
		if (relay->group != group)
			continue;
		HASH_DEL(txn_relays, relay);
		free(relay);
	}
	if (txn_relay_pending == group)
		txn_relay_pending = NULL;
	if (group->payload)
		dealloc(group->payload);
	free(group);
}

static bool peer_sent_block(int peer, const blocklist_t *block)
{
	int i;

	if (!block || peer < 0)
		return false;
	if (block->source == peer)
		return true;
	ck_rlock(&curblock.lock);
	if (!memcmp(fastsources.hash, block->hash, 32)) {
		for (i = 0; i < fastsources.count; i++) {
			if (fastsources.peers[i] == peer) {
				ck_runlock(&curblock.lock);
				return true;
			}
		}
	}
	ck_runlock(&curblock.lock);
	return false;
}

/* Try to add a connection as a txn relay source. Returns true if added. */
static bool try_add_txn_relay_conn(p2p_conn_t *sc, int *sent, int conn_peers[],
				   p2p_conn_t *conns[])
{
	int i, peer;
	txn_relay_t *busy;

	if (!sc || !sc->peer || *sent >= FAST_SOURCES_MAX)
		return false;
	peer = sc->peer;

	for (i = 0; i < *sent; i++) {
		if (conn_peers[i] == peer)
			return false;
	}

	ck_rlock(&txn_relay_lock);
	HASH_FIND_INT(txn_relays, &peer, busy);
	ck_runlock(&txn_relay_lock);

	if (busy)
		return false;

	if (unlikely(sc->evicted) || sc->sock < 0 || !sc->handshake_done)
		return false;

	conns[*sent] = sc;
	conn_peers[(*sent)++] = peer;
	return true;
}

static bool try_add_txn_relay_peer(int peer, int *sent, int conn_peers[],
				   p2p_conn_t *conns[])
{
	return try_add_txn_relay_conn(get_peer(peer), sent, conn_peers, conns);
}

/* Add slow p2p peers that did not send this compact block. */
static int add_slow_txn_sources(const blocklist_t *block, int sent,
				int conn_peers[], p2p_conn_t *conns[])
{
	peerlist_t *p2ppeer;
	int slow_added = 0, slow_max;

	slow_max = SLOW_SOURCES_MAX - sent;
	if (slow_max < 1)
		return sent;

	ck_rlock(&peerlock);
	for (p2ppeer = p2ppeers; p2ppeer && slow_added < slow_max && sent < FAST_SOURCES_MAX;
	     p2ppeer = p2ppeer->hh.next) {
		p2p_conn_t *conn = p2ppeer->conn;
		int peer;

		if (!conn)
			continue;
		peer = conn->peer;
		if (peer < ckpool.prioclients)
			continue;
		if (peer_sent_block(peer, block))
			continue;
		if (try_add_txn_relay_conn(conn, &sent, conn_peers, conns))
			slow_added++;
	}
	ck_runlock(&peerlock);

	if (slow_added)
		LOGWARNING("Added %d slow sources for txn relay (%d total)", slow_added, sent);
	return sent;
}

static bool skip_bytes(uint32_t dlen, uint32_t *pos, uint32_t len)
{
	if (*pos + len > dlen)
		return false;
	*pos += len;
	return true;
}

static bool skip_script(const uchar *data, uint32_t dlen, uint32_t *pos)
{
	int64_t slen = parse_varint(data, dlen, pos);

	if (slen < 0 || (uint64_t)slen > dlen - *pos)
		return false;
	*pos += slen;
	return true;
}

/* Return serialized byte length of one transaction, or -1 on error. */
static int parse_tx_size(const uchar *data, uint32_t dlen, uint32_t start)
{
	uint32_t pos = start;
	int64_t vin, vout, i, stack, j;
	bool witness = false;

	if (start >= dlen || !skip_bytes(dlen, &pos, 4))
		return -1;

	if (pos + 2 <= dlen && !data[pos] && data[pos + 1] == 1) {
		witness = true;
		pos += 2;
	}

	vin = parse_varint(data, dlen, &pos);
	if (vin < 0)
		return -1;
	for (i = 0; i < vin; i++) {
		if (!skip_bytes(dlen, &pos, 36) || !skip_script(data, dlen, &pos) ||
		    !skip_bytes(dlen, &pos, 4))
			return -1;
	}

	vout = parse_varint(data, dlen, &pos);
	if (vout < 0)
		return -1;
	for (i = 0; i < vout; i++) {
		if (!skip_bytes(dlen, &pos, 8) || !skip_script(data, dlen, &pos))
			return -1;
	}

	if (witness) {
		for (i = 0; i < vin; i++) {
			stack = parse_varint(data, dlen, &pos);
			if (stack < 0)
				return -1;
			for (j = 0; j < stack; j++) {
				if (!skip_script(data, dlen, &pos))
					return -1;
			}
		}
	}

	if (!skip_bytes(dlen, &pos, 4))
		return -1;

	return pos - start;
}

static void store_peer0_tx(const uchar *data, uint32_t len)
{
	peer0_tx_t *tx = ckalloc(sizeof(peer0_tx_t));

	tx->data = ckalloc(len);
	memcpy(tx->data, data, len);
	tx->len = len;
	ck_wlock(&pending_peer0_tx_lock);
	DL_APPEND(pending_peer0_txs, tx);
	ck_wunlock(&pending_peer0_tx_lock);
}

static void free_peer0_tx(peer0_tx_t *tx)
{
	if (tx->data)
		dealloc(tx->data);
	free(tx);
}

static void flush_pending_peer0_txs(p2p_conn_t *peer0)
{
	peer0_tx_t *tx, *tmp, *list = NULL;
	int submitted = 0;

	if (!peer0 || peer0->sock < 0 || !peer0->handshake_done)
		return;

	ck_wlock(&pending_peer0_tx_lock);
	DL_FOREACH_SAFE(pending_peer0_txs, tx, tmp) {
		DL_DELETE(pending_peer0_txs, tx);
		DL_APPEND(list, tx);
	}
	ck_wunlock(&pending_peer0_tx_lock);

	DL_FOREACH_SAFE(list, tx, tmp) {
		p2p_send(peer0, "tx", tx->data, tx->len);
		submitted++;
		DL_DELETE(list, tx);
		free_peer0_tx(tx);
	}

	if (submitted)
		LOGWARNING("Submitted %d queued transactions to peer 0", submitted);
}

static void submit_blocktxn_to_peer0(const uchar *payload, uint32_t plen)
{
	uint32_t pos = 32;
	int64_t count, i;
	int handled = 0;
	p2p_conn_t *peer0;
	bool submit_now;

	if (plen < 33) {
		LOGWARNING("Blocktxn too short to parse");
		return;
	}

	peer0 = get_peer(0);
	submit_now = peer0 && peer0->sock >= 0 && peer0->handshake_done;

	count = parse_varint(payload, plen, &pos);
	if (count < 0 || count > 100000) {
		LOGWARNING("Invalid blocktxn transaction count %lld", (long long)count);
		return;
	}

	for (i = 0; i < count; i++) {
		int txlen = parse_tx_size(payload, plen, pos);

		if (txlen < 0) {
			LOGWARNING("Failed to parse blocktxn transaction %lld/%lld",
				   (long long)i, (long long)count);
			return;
		}
		if (pos + (uint32_t)txlen > plen) {
			LOGWARNING("Blocktxn transaction %lld overflows payload", (long long)i);
			return;
		}
		if (submit_now)
			p2p_send(peer0, "tx", payload + pos, (uint32_t)txlen);
		else
			store_peer0_tx(payload + pos, (uint32_t)txlen);
		pos += txlen;
		handled++;
	}

	if (!handled)
		return;
	if (submit_now)
		LOGWARNING("Submitted %d blocktxn transactions to peer 0", handled);
	else
		LOGWARNING("Queued %d blocktxn transactions for peer 0 reconnect", handled);
}

/* Register pending relays and forward getblocktxn to fast and slow sources. */
static bool forward_getblocktxn(blocklist_t *block, const uchar *payload, uint32_t plen)
{
	txn_relay_group_t *group;
	int sources[FAST_SOURCES_MAX];
	int source_count, i, sent = 0;
	p2p_conn_t *conns[FAST_SOURCES_MAX];
	int conn_peers[FAST_SOURCES_MAX];

	if (!block) {
		LOGNOTICE("No block found for forward_getblocktxn");
		return false;
	}

	ck_wlock(&txn_relay_lock);
	if (txn_relay_pending) {
		ck_wunlock(&txn_relay_lock);
		LOGNOTICE("Txn relay already pending for peer 0");
		return false;
	}
	ck_wunlock(&txn_relay_lock);

	ck_rlock(&curblock.lock);
	if (memcmp(fastsources.hash, block->hash, 32)) {
		source_count = 0;
		if (block->source >= 0) {
			sources[0] = block->source;
			source_count = 1;
		}
	} else {
		source_count = fastsources.count;
		memcpy(sources, fastsources.peers, source_count * sizeof(int));
	}
	ck_runlock(&curblock.lock);

	for (i = 0; i < source_count && sent < FAST_SOURCES_MAX; i++) {
		if (!sources[i])
			continue;
		try_add_txn_relay_peer(sources[i], &sent, conn_peers, conns);
	}

	if (sent < FAST_SOURCES_MAX)
		sent = add_slow_txn_sources(block, sent, conn_peers, conns);

	if (!sent)
		return false;

	group = ckalloc(sizeof(txn_relay_group_t));
	group->block = block;
	group->payload = ckalloc(plen);
	memcpy(group->payload, payload, plen);
	group->plen = plen;
	tv_monotonic(&group->sent);
	group->pending = sent;
	group->done = false;

	ck_wlock(&txn_relay_lock);
	txn_relay_pending = group;
	for (i = 0; i < sent; i++) {
		txn_relay_t *relay = ckalloc(sizeof(txn_relay_t));

		relay->source_peer = conn_peers[i];
		relay->group = group;
		HASH_ADD_INT(txn_relays, source_peer, relay);
	}
	ck_wunlock(&txn_relay_lock);

	for (i = 0; i < sent; i++)
		p2p_send(conns[i], "getblocktxn", payload, plen);

	return true;
}

/* Parse the first blocktxn response and submit its transactions to peer 0. */
static void handle_blocktxn_relay(p2p_conn_t *source, uchar *payload, uint32_t plen)
{
	txn_relay_t *relay;
	txn_relay_group_t *group;
	bool forward = false;

	ck_wlock(&txn_relay_lock);
	HASH_FIND_INT(txn_relays, &source->peer, relay);
	if (!relay) {
		ck_wunlock(&txn_relay_lock);
		LOGINFO("Got BLOCKTXN from expired txn_relay");
		goto out;
	}
	group = relay->group;
	if (!group->done)
		forward = true;
	group->done = true;
	delete_txn_relay_group_locked(group);
	ck_wunlock(&txn_relay_lock);

	if (!forward)
		goto out;

	LOGWARNING("Received blocktxn (%u bytes) from peer %d - submitting transactions to peer 0",
		   plen, source->peer);
	submit_blocktxn_to_peer0(payload, plen);
out:
	dealloc(payload);
}

static void expire_txn_relays(tv_t *now)
{
	txn_relay_group_t *group;
	p2p_conn_t *requester;
	bool timed_out;

	ck_wlock(&txn_relay_lock);
	group = txn_relay_pending;
	if (!group) {
		ck_wunlock(&txn_relay_lock);
		return;
	}
	if (ms_tvdiff(now, &group->sent) >= 0 &&
	    ms_tvdiff(now, &group->sent) < TXN_RELAY_TIMEOUT_MS) {
		ck_wunlock(&txn_relay_lock);
		return;
	}
	timed_out = !group->done;
	delete_txn_relay_group_locked(group);
	ck_wunlock(&txn_relay_lock);

	if (!timed_out)
		return;

	LOGWARNING("Txn relay timed out for peer 0");
	requester = get_peer(0);
	if (requester && requester->sock >= 0) {
		disconnect_conn(requester);
		add_connector(requester);
	}
}

static void *p2p_txn_relay_watcher(void __maybe_unused *arg)
{
	tv_t now;

	pthread_detach(pthread_self());
	rename_proc("ckp2ptr");

	while (42) {
		cksleep_ms(TXN_RELAY_POLL_MS);
		tv_monotonic(&now);
		expire_txn_relays(&now);
	}
	return NULL;
}

/* Function for testing cmpctblock validity by echoing back any received */
static void handle_cmpctblock(uchar *payload, uint32_t plen, int source)
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
		if (current_bits > block_bits || source < ckpool.prioclients) {
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
		LOGWARNING("Dropping shitcoin peer %d not meeting difficulty target (0x%08x)",
			   source, current_bits);
		dealloc(payload);
		evict_peerno(source);
		return;
	}

	add_fast_source(blockhash, source);

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
			block->source = source;
			DL_APPEND(blockhashes, block);
			DL_COUNT(blockhashes, block, count);
			LOGDEBUG("Block count %d", count);
			if (count > 100) {
				blocklist_t *old = blockhashes;

				if (!block_has_pending_relay(old)) {
					DL_DELETE(blockhashes, old);
					free(old);
				}
			}
			memcpy(curblock.hash, blockhash, 32);
			new_block = true;
		} else
			LOGDEBUG("Block already exists");
	}
	ck_wunlock(&curblock.lock);

	if (new_block) {
		display_newblock(blockhash, source);
		relay_compact_block(blockhash, payload, plen, shortid_nonce, source);
		dump_blocks_txt();
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
			if (reject_blocksonly_peer(conn, payload, plen)) {
				dealloc(payload);
				close(conn->sock);
				conn->sock = -1;
				return false;
			}
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
static bool _dup_peer(const char *host, int port)
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

static bool dup_peer(const char *host, int port)
{
	bool ret;

	ck_rlock(&peerlock);
	ret = _dup_peer(host, port);
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
			if (dup_peer(conn->host, conn->port)) {
				LOGNOTICE("Duplicate incoming peer %s:%s, will not reconnect if dropped", conn->host, conn->charport);
				conn->incoming_only = true;
			}

			if (reject_blocksonly_peer(conn, payload, plen)) {
				dealloc(payload);
				close(conn->sock);
				conn->sock = -1;
				return false;
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
	if (unlikely(_dup_peer(conn->host, conn->port))) {
		ck_wunlock(&peerlock);
		LOGINFO("Skipping duplicate peer %s:%d", conn->host, conn->port);
		disconnect_conn(conn);
		dealloc(conn);
		goto out;
	}

	/* Dynamically grow the peer lists (p2purl, p2pcs, p2pconn) */
	int old = ckpool.p2purls;

	/* p2purl */
	char **old_p2purl = ckpool.p2purl;
	ckpool.p2purl = ckalloc(sizeof(char *) * (old + 1));
	if (old > 0)
		memcpy(ckpool.p2purl, old_p2purl, sizeof(char *) * old);
	char *new_url = ckalloc(strlen(conn->host) + strlen(conn->charport) + 2);
	sprintf(new_url, "%s:%s", conn->host, conn->charport);
	ckpool.p2purl[old] = new_url;
	if (old_p2purl) dealloc(old_p2purl);

	/* p2pcs (for API consistency) */
	connsock_t **old_p2pcs = ckpool.p2pcs;
	ckpool.p2pcs = ckalloc(sizeof(connsock_t *) * (old + 1));
	if (old > 0)
		memcpy(ckpool.p2pcs, old_p2pcs, sizeof(connsock_t *) * old);
	ckpool.p2pcs[old] = NULL;
	if (old_p2pcs) dealloc(old_p2pcs);

	/* p2pconn */
	p2p_conn_t **old_p2pconn = ckpool.p2pconn;
	ckpool.p2pconn = ckalloc(sizeof(p2p_conn_t *) * (old + 1));
	if (old > 0)
		memcpy(ckpool.p2pconn, old_p2pconn, sizeof(p2p_conn_t *) * old);
	ckpool.p2pconn[old] = conn;
	if (old_p2pconn) dealloc(old_p2pconn);

	conn->peer = old;
	ckpool.p2purls = old + 1;
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

static void add_peer_async(const char *host, int port)
{
	pthread_t pthread;
	p2p_conn_t *conn;

	LOGINFO("New addrv2: %s:%d", host, port);
	if (!finished_init)
		return;

	conn = ckzalloc(sizeof(*conn));
	cklock_init(&conn->block_lock);
	conn->sock = -1;
	strncpy(conn->host, host, sizeof(conn->host) - 1);
	snprintf(conn->charport, sizeof(conn->charport), "%d", port);
	conn->port = port;
	memcpy(conn->magic, netdefs[0].magic, 4);
	memcpy(conn->genesis, netdefs[0].genesis, 32);
	conn->netname = netdefs[0].name;
	conn->peer = -1;
	peer_alive(conn);

	create_pthread(&pthread, add_peer, conn);
}

static inline bool client_watermarks(void)
{
	bool ret = true;

	if (total_conns >= ckpool.maxclients * 4 / 3)
		goto out;
	if (active_conns >= ckpool.maxclients)
		goto out;
	ret = false;
out:
	return ret;
}

static bool pause_clients(void)
{
	bool ret = true;

	if (client_watermarks())
		goto out;
	if (connectors_woken() >= num_threads)
		goto out;
	ret = false;
out:
	return ret;
}

/* Parse an ADDRV2 message and extract/log all host:port pairs.
 * Supports IPv4 (netid=1) and IPv6 (netid=2). */
static void parse_addrv2(uchar *data, uint32_t dlen)
{
	uint32_t pos = 0;
	int i, count;

	if (pause_clients()) {
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

		if (!dup_peer(host, port))
			add_peer_async(host, port);
		else
			LOGINFO("Dup addrv2: %s:%d", host, port);

	next:
		continue;
	}
out:
	dealloc(data);
}

static void *p2p_receiver(void __maybe_unused *arg)
{
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
		p2purls = ckpool.p2purls;
		ck_runlock(&peerlock);

		if (unlikely(idx >= (uint64_t)p2purls)) {
			LOGINFO("invalid peer index %"PRId64, idx);
			continue;
		}

		conn = get_peer(idx);
		if (unlikely(!conn || conn->evicted))
			continue;

		if (event.events & EPOLLIN)
			add_reader(conn);
		else
			add_connector(conn);
	}
	return NULL;
}

static void p2p_connector(p2p_conn_t *conn)
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

	if (!conn->peer && conn->handshake_done)
		flush_pending_peer0_txs(conn);

	try_startup_bits_request(conn);
	add_reader(conn);
out:
	del_connector(conn);
	return;
}

static void p2p_reader(p2p_conn_t *conn)
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
		handle_cmpctblock(payload, plen, conn->peer);
		goto rearm;
	} else if (!strcmp(cmd, "tx")) {
		LOGDEBUG("Received TX (%u bytes) - ignoring (transaction data)", plen);
	} else if (!strcmp(cmd, "block")) {
		LOGINFO("Received BLOCK (%u bytes) - ignoring (full block data)", plen);
	} else if (!strcmp(cmd, "blocktxn")) {
		LOGDEBUG("Received BLOCKTXN (%u bytes) - handling (block transactions response)", plen);
		handle_blocktxn_relay(conn, payload, plen);
		goto rearm;
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
		parse_addrv2(payload, plen);
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
static void dump_peers(void)
{
	peerlist_t *p2ppeer;
	int count = 0;
	FILE *fp;

	fp = fopen("peers.conf", "we");
	if (unlikely(!fp)) {
		LOGERR("Unable to fopen peers.conf in dump_peers");
		return;
	}
	fprintf(fp, "{\n\"maxclients\" : %d,\n", ckpool.maxclients);
	fprintf(fp, "\"prioclients\" : %d,\n", ckpool.prioclients);
	fprintf(fp, "\"externalip\" : \"%s\",\n", ckpool.externalip);
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

static void *p2p_keepalive(void __maybe_unused *arg)
{
	ts_t last_update;
	tv_t last_ping;

	tv_monotonic(&last_ping);
	cksleep_prepare_r(&last_update);

	pthread_detach(pthread_self());
	rename_proc("ckp2pk");

	while (42) {
		uint64_t nonce, nonce_le;
		bool ping = false;
		int p2purls, i;
		tv_t now;

		ck_rlock(&peerlock);
		p2purls = ckpool.p2purls;
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
			dump_peers();
		}

		for (i = 0; i < p2purls ; i++) {
			p2p_conn_t *conn = get_peer(i);

			if (unlikely(!conn))
				continue;
			if (conn->evicted)
				continue;
			if (!conn->handshake_done || conn->sock < 0) {
				int attempted, timeout = EVICT_TIMEOUT;
				bool prio;

				if (conn->incoming_only) {
					evict_peer(conn);
					continue;
				}

				prio = (i < ckpool.prioclients);
				/* Never evict priority clients */
				if (!prio) {
					int unresponsive = tvdiff(&now, &conn->last_alive);

					if (client_watermarks())
						timeout = FAST_EVICT;
					if (unresponsive >= timeout) {
						LOGWARNING("Dropping peer %d unresponsive for %d seconds",
							   conn->peer, unresponsive);
						evict_peer(conn);
						continue;
					}
				}

				attempted = tvdiff(&now, &conn->last_attempt);
				/* Double reconnect timeout each time. Priority
				 * clients have a reconnect of 0 */
				if (attempted >= conn->reconnect) {
					if (conn->reconnect < 300)
						conn->reconnect *= 2;
					add_connector(conn);
				}
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
	int i, submitted = 0;
	int p2purls;

	pthread_detach(pthread_self());

	ck_rlock(&peerlock);
	p2purls = ckpool.p2purls;
	ck_runlock(&peerlock);

	for (i = 0; i < p2purls; i++) {
		p2p_conn_t *conn;

		/* Only relay to prioclients unless the compact block has come
		 * from the local peer 0 source */
		if (cbt->source && i >= ckpool.prioclients)
			break;

		if (i == cbt->source) {
			LOGDEBUG("Skipping relaying compact block to source node %d", i);
			continue;
		}

		conn = get_peer(i);
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

		/* Disconnect all priority peers except peer 0 which should be
		 * localhost to avoid inducing latency at their end in case they
		 * ask for more information from ckp2p.*/
		if (i && i < ckpool.prioclients) {
			disconnect_conn(conn);
			add_connector(conn);
		}

		submitted++;
	}

	bswap_256(fliphash, cbt->blockhash);
	__bin2hex(hex, fliphash, 32);
	if (submitted)
		LOGWARNING("Submitted %d compact block%s %s", submitted, submitted > 1 ? "s" : "", hex);
	free(cbt->cmpct_payload);
	free(cbt);

	return NULL;
}

static void relay_compact_block(const uchar *blockhash, uchar *cmpct_payload,
				uint32_t cmpct_len, uint64_t shortid_nonce, int source)
{
	compact_block_t *cbt = ckalloc(sizeof(compact_block_t));

	memcpy(cbt->blockhash, blockhash, 32);
	/* Steal payload memory here */
	cbt->cmpct_payload = cmpct_payload;
	cbt->cmpct_len = cmpct_len;
	cbt->shortid_nonce = shortid_nonce;
	cbt->source = source;

	create_pthread(&cbt->pth, submission_thread, cbt);
}

void submit_compact_block(const uchar *blockhash, uchar *cmpct_payload,
			  uint32_t cmpct_len, uint64_t shortid_nonce)
{
	relay_compact_block(blockhash, cmpct_payload, cmpct_len, shortid_nonce, -1);
}

static p2p_conn_t *ckp2p_connect(const char *host, const char *charport, int source)
{
	p2p_conn_t *conn = ckzalloc(sizeof(*conn));
	int port, i;

	cklock_init(&conn->block_lock);
	conn->peer = source;
	conn->sock = -1;
	strncpy(conn->host, host, sizeof(conn->host) - 1);
	strncpy(conn->charport, charport, sizeof(conn->charport) - 1);
	sscanf(charport, "%d", &port);
	conn->port = port;

	/* Set initial attempted connection time */
	peer_alive(conn);

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

	if (source < ckpool.prioclients)
		LOGWARNING("ckp2p set up prio peer %d - %s:%s", source, host, charport);
	else
		LOGNOTICE("ckp2p set up config peer %d - %s:%s", source, host, charport);

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
static void *p2p_acceptor(void __maybe_unused *arg)
{
	pthread_detach(pthread_self());
	rename_proc("ckp2pa");

	int listen_sock = create_p2p_listener();
	if (listen_sock < 0)
		return NULL;

	while (42) {
		struct sockaddr_in client_addr;
		socklen_t clen = sizeof(client_addr);
		int newsock;

		while (client_watermarks())
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
		cklock_init(&conn->block_lock);
		conn->sock = newsock;
		strncpy(conn->host, host, sizeof(conn->host) - 1);
		strncpy(conn->charport, serv, sizeof(conn->charport) - 1);
		conn->port = port_num;
		memcpy(conn->genesis, netdefs[0].genesis, 32);
		conn->netname = netdefs[0].name;
		conn->peer = -1;
		peer_alive(conn);

		if (!do_incoming_handshake(conn)) {
			LOGINFO("Incoming handshake failed from %s:%d", host, port_num);
			close(newsock);
			dealloc(conn);
			continue;
		}

		ck_wlock(&peerlock);
		/* Dynamically grow the peer lists (p2purl, p2pcs, p2pconn) */
		int old = ckpool.p2purls;

		/* p2purl */
		char **old_p2purl = ckpool.p2purl;
		ckpool.p2purl = ckalloc(sizeof(char *) * (old + 1));
		if (old > 0)
			memcpy(ckpool.p2purl, old_p2purl, sizeof(char *) * old);
		char *new_url = ckalloc(strlen(host) + strlen(serv) + 2);
		sprintf(new_url, "%s:%s", host, serv);
		ckpool.p2purl[old] = new_url;
		if (old_p2purl) dealloc(old_p2purl);

		/* p2pcs (for API consistency) */
		connsock_t **old_p2pcs = ckpool.p2pcs;
		ckpool.p2pcs = ckalloc(sizeof(connsock_t *) * (old + 1));
		if (old > 0)
			memcpy(ckpool.p2pcs, old_p2pcs, sizeof(connsock_t *) * old);
		ckpool.p2pcs[old] = NULL;
		if (old_p2pcs) dealloc(old_p2pcs);

		/* p2pconn */
		p2p_conn_t **old_p2pconn = ckpool.p2pconn;
		ckpool.p2pconn = ckalloc(sizeof(p2p_conn_t *) * (old + 1));
		if (old > 0)
			memcpy(ckpool.p2pconn, old_p2pconn, sizeof(p2p_conn_t *) * old);
		ckpool.p2pconn[old] = conn;
		if (old_p2pconn)
			dealloc(old_p2pconn);

		conn->peer = old;
		ckpool.p2purls = old + 1;
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

int prepare_ckp2p(void)
{
	pthread_t pthread;
	connsock_t *cs;
	int i, p2purls;

	cklock_init(&curblock.lock);
	load_blocks_txt();
	cklock_init(&peerlock);
	cklock_init(&txn_relay_lock);
	cklock_init(&pending_peer0_tx_lock);

	if (ckpool.externalip) {
		connsock_t cslocal = {};
		struct in_addr addr;

		if (!extract_sockaddr(ckpool.externalip, &cslocal.url, &cslocal.port)) {
			LOGEMERG("Failed to extract address from externalip %s", ckpool.externalip);
			return -1;
		}
		if (inet_aton(cslocal.url, &addr) == 0) {
			LOGEMERG("Failed to parse IP from externalip %s", ckpool.externalip);
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
		ASPRINTF(&ckpool.externalip, "127.0.0.1:%d", externalport);
	}

	if (ckpool.p2purls > ckpool.maxclients * 4 / 3) {
		ckpool.p2purls = ckpool.maxclients * 4 / 3;
		LOGWARNING("Limiting peers to %d", ckpool.p2purls);
	}
	p2purls = total_conns = ckpool.p2purls;
	ckpool.p2pconn = ckzalloc(sizeof(p2p_conn_t *) * ckpool.p2purls);
	ckpool.p2pcs = ckzalloc(sizeof(connsock_t *) * ckpool.p2purls);
	for (i = 0 ; i < ckpool.p2purls ; i++) {
		ckpool.p2pcs[i] = ckzalloc(sizeof(connsock_t));
		cs = ckpool.p2pcs[i];
		if (!extract_sockaddr(ckpool.p2purl[i], &cs->url, &cs->port)) {
			LOGEMERG("Failed to extract address from p2purl %s", ckpool.p2purl[i]);
			return -1;
		}
	}

	for (i = 0 ; i < p2purls ; i++) {
		cs = ckpool.p2pcs[i];
		p2p_conn_t *conn = ckpool.p2pconn[i] = ckp2p_connect(cs->url, cs->port, i);
		peerlist_t *p2ppeer = conn->p2ppeer = ckalloc(sizeof(peerlist_t));
		p2ppeer->conn = conn;
		sprintf(p2ppeer->url, "%s", ckpool.p2purl[i]);
		HASH_ADD_STR(p2ppeers, url, p2ppeer);
	}
	LOGWARNING("ckp2p finished attempting bitcoin node connections.");

	num_threads = sysconf(_SC_NPROCESSORS_ONLN);
	p2p_readers = create_ckmsgqs("p2pread", &p2p_reader, num_threads);
	p2p_connectors = create_ckmsgqs("p2pconnect", &p2p_connector, num_threads);

	reader_epfd = epoll_create1(EPOLL_CLOEXEC);
	if (reader_epfd < 0)
		quit(1, "FATAL: Failed to create epoll in prepare_ckp2p");

	create_pthread(&pthread, p2p_receiver, NULL);
	create_pthread(&pthread, p2p_keepalive, NULL);
	create_pthread(&pthread, p2p_txn_relay_watcher, NULL);

	/* Start listener thread for incoming ckp2p connections on port 8335 */
	create_pthread(&pthread, p2p_acceptor, NULL);
	LOGWARNING("ckp2p listener thread started for incoming connections on port %d", externalport);

	ck_wlock(&peerlock);
	for (i = 0; i < p2purls; i++)
		_add_connector(ckpool.p2pconn[i]);
	ck_wunlock(&peerlock);

	finished_init = true;

	return 0;
}
