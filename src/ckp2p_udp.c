/*
 * Copyright 2026 Con Kolivas
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 3 of the License, or (at your option)
 * any later version.  See COPYING for more details.
 */

#include "config.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "libckpool.h"
#include "ckpool.h"
#include "ckp2p_udp.h"
#include "utlist.h"

#define P2P_UDP_TYPE_HELLO	1
#define P2P_UDP_TYPE_HELLOACK	2
#define P2P_UDP_TYPE_PING	3
#define P2P_UDP_TYPE_PONG	4
#define P2P_UDP_TYPE_MSG	5
#define P2P_UDP_VER		1
#define P2P_UDP_GROUP_EXPIRE	2.0

static int udp_fd = -1;
static uchar udp_magic[4] = {0xf9, 0xbe, 0xb4, 0xd9};
static uchar udp_genesis[32];

struct fec_group {
	struct fec_group *next, *prev;
	uint64_t msg_id;
	uint16_t group;
	uint16_t ngroups;
	uint16_t k;
	uint16_t n;
	uint32_t total_len;
	char cmd[13];
	char ip[INET6_ADDRSTRLEN];
	p2p_conn_t *conn;
	uchar *shards[P2P_FEC_MAX_N];
	unsigned idxs[P2P_FEC_MAX_N];
	bool have[P2P_FEC_MAX_N];
	int got;
	tv_t started;
};

struct fec_msg {
	struct fec_msg *next, *prev;
	uint64_t msg_id;
	uint16_t ngroups;
	uint32_t total_len;
	char cmd[13];
	char ip[INET6_ADDRSTRLEN];
	p2p_conn_t *conn;
	uchar **parts;
	uint32_t *plens;
	bool *haveg;
	int got;
	tv_t started;
};

static struct fec_group *fec_groups;
static struct fec_msg *fec_msgs;

int p2p_udp_fd(void)
{
	return udp_fd;
}

void p2p_udp_set_magic(const uchar magic[4])
{
	memcpy(udp_magic, magic, 4);
}

void p2p_udp_set_genesis(const uchar genesis[32])
{
	memcpy(udp_genesis, genesis, 32);
}

void p2p_udp_canon_ip(const struct sockaddr *sa, char *out, size_t outlen)
{
	if (!sa || !out || !outlen)
		return;
	out[0] = 0;
	if (sa->sa_family == AF_INET) {
		const struct sockaddr_in *in = (const struct sockaddr_in *)sa;

		inet_ntop(AF_INET, &in->sin_addr, out, outlen);
	} else if (sa->sa_family == AF_INET6) {
		const struct sockaddr_in6 *in6 = (const struct sockaddr_in6 *)sa;

		if (IN6_IS_ADDR_V4MAPPED(&in6->sin6_addr))
			inet_ntop(AF_INET, &in6->sin6_addr.s6_addr[12], out, outlen);
		else
			inet_ntop(AF_INET6, &in6->sin6_addr, out, outlen);
	}
}

void p2p_udp_canon_ip_str(const char *host, char *out, size_t outlen)
{
	struct in6_addr a6;
	struct in_addr a4;

	if (!host || !out || !outlen)
		return;
	out[0] = 0;
	if (inet_pton(AF_INET, host, &a4) == 1) {
		inet_ntop(AF_INET, &a4, out, outlen);
		return;
	}
	if (inet_pton(AF_INET6, host, &a6) == 1) {
		if (IN6_IS_ADDR_V4MAPPED(&a6))
			inet_ntop(AF_INET, &a6.s6_addr[12], out, outlen);
		else
			inet_ntop(AF_INET6, &a6, out, outlen);
		return;
	}
	snprintf(out, outlen, "%s", host);
}

bool p2p_udp_fill_dst(p2p_conn_t *conn, const char *host, int port)
{
	struct addrinfo hints, *res, *rp;
	char serv[16];
	int rc;

	if (!conn || !host)
		return false;
	snprintf(serv, sizeof(serv), "%d", port);
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_DGRAM;
	rc = getaddrinfo(host, serv, &hints, &res);
	if (rc)
		return false;
	for (rp = res; rp; rp = rp->ai_next) {
		if (rp->ai_addrlen > sizeof(conn->udp_dst))
			continue;
		memset(&conn->udp_dst, 0, sizeof(conn->udp_dst));
		memcpy(&conn->udp_dst, rp->ai_addr, rp->ai_addrlen);
		conn->udp_dstlen = rp->ai_addrlen;
		freeaddrinfo(res);
		return true;
	}
	freeaddrinfo(res);
	return false;
}

static int bind_udp(int port)
{
	struct sockaddr_in6 sin6;
	struct sockaddr_in sin;
	int sock, opt, v6only;

	sock = socket(AF_INET6, SOCK_DGRAM, 0);
	if (sock >= 0) {
		opt = 1;
		setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
		v6only = 0;
		setsockopt(sock, IPPROTO_IPV6, IPV6_V6ONLY, &v6only, sizeof(v6only));
		opt = 1 << 20;
		setsockopt(sock, SOL_SOCKET, SO_RCVBUF, &opt, sizeof(opt));
		memset(&sin6, 0, sizeof(sin6));
		sin6.sin6_family = AF_INET6;
		sin6.sin6_port = htons(port);
		sin6.sin6_addr = in6addr_any;
		if (!bind(sock, (struct sockaddr *)&sin6, sizeof(sin6)))
			return sock;
		close(sock);
	}

	sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock < 0)
		return -1;
	opt = 1;
	setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
	opt = 1 << 20;
	setsockopt(sock, SOL_SOCKET, SO_RCVBUF, &opt, sizeof(opt));
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_port = htons(port);
	sin.sin_addr.s_addr = htonl(INADDR_ANY);
	if (bind(sock, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
		close(sock);
		return -1;
	}
	return sock;
}

int p2p_udp_init(int port)
{
	udp_fd = bind_udp(port);
	if (udp_fd < 0) {
		LOGEMERG("Failed to bind ckp2p UDP port %d: %s", port, strerror(errno));
		return -1;
	}
	LOGNOTICE("ckp2p UDP listening on port %d", port);
	return udp_fd;
}

static bool udp_sendto(p2p_conn_t *conn, const uchar *pkt, size_t len)
{
	ssize_t n;

	if (udp_fd < 0 || !conn || conn->udp_dstlen <= 0)
		return false;
	if (len > P2P_UDP_MAXPKT)
		return false;
	n = sendto(udp_fd, pkt, len, 0, (struct sockaddr *)&conn->udp_dst,
		   conn->udp_dstlen);
	if (n != (ssize_t)len) {
		LOGINFO("UDP sendto failed for peer %d: %s", conn->peer, strerror(errno));
		return false;
	}
	return true;
}

static void pack_le16(uchar *p, uint16_t v)
{
	uint16_t le = htole16(v);

	memcpy(p, &le, 2);
}

static void pack_le32(uchar *p, uint32_t v)
{
	uint32_t le = htole32(v);

	memcpy(p, &le, 4);
}

static void pack_le64(uchar *p, uint64_t v)
{
	uint64_t le = htole64(v);

	memcpy(p, &le, 8);
}

static uint16_t unpack_le16(const uchar *p)
{
	uint16_t le;

	memcpy(&le, p, 2);
	return le16toh(le);
}

static uint32_t unpack_le32(const uchar *p)
{
	uint32_t le;

	memcpy(&le, p, 4);
	return le32toh(le);
}

static uint64_t unpack_le64(const uchar *p)
{
	uint64_t le;

	memcpy(&le, p, 8);
	return le64toh(le);
}

static int pack_ctrl(uchar *pkt, uint8_t type, uint64_t nonce)
{
	memcpy(pkt, udp_magic, 4);
	pkt[4] = type;
	pkt[5] = P2P_UDP_VER;
	pkt[6] = 0;
	pkt[7] = 0;
	pack_le64(pkt + 8, nonce);
	return 16;
}

bool p2p_udp_hello(p2p_conn_t *conn)
{
	uchar pkt[128];
	const char *ua = P2P_UDP_UA;
	uchar ualen;
	int off;

	if (!conn)
		return false;
	if (!conn->udp_hello_nonce)
		conn->udp_hello_nonce = ((uint64_t)rand() << 32) | rand();
	conn->udp_hello_acked = false;
	ualen = (uchar)strlen(ua);
	off = pack_ctrl(pkt, P2P_UDP_TYPE_HELLO, conn->udp_hello_nonce);
	pkt[off++] = ualen;
	memcpy(pkt + off, ua, ualen);
	off += ualen;
	memcpy(pkt + off, conn->genesis[0] ? conn->genesis : udp_genesis, 32);
	off += 32;
	if (!udp_sendto(conn, pkt, off))
		return false;
	LOGINFO("UDP HELLO to peer %d %s:%d", conn->peer, conn->host, conn->port);
	return true;
}

static bool send_helloack(p2p_conn_t *conn, uint64_t nonce)
{
	uchar pkt[128];
	const char *ua = P2P_UDP_UA;
	uchar ualen;
	int off;

	ualen = (uchar)strlen(ua);
	off = pack_ctrl(pkt, P2P_UDP_TYPE_HELLOACK, nonce);
	pkt[off++] = ualen;
	memcpy(pkt + off, ua, ualen);
	off += ualen;
	memcpy(pkt + off, udp_genesis, 32);
	off += 32;
	return udp_sendto(conn, pkt, off);
}

bool p2p_udp_hello_wait(p2p_conn_t *conn, int timeout_ms)
{
	int waited = 0;

	if (!conn)
		return false;
	while (waited < timeout_ms) {
		if (conn->udp_hello_acked)
			return true;
		cksleep_ms(10);
		waited += 10;
	}
	return conn->udp_hello_acked;
}

void p2p_udp_ping(p2p_conn_t *conn, uint64_t nonce)
{
	uchar pkt[16];

	pack_ctrl(pkt, P2P_UDP_TYPE_PING, nonce);
	udp_sendto(conn, pkt, 16);
}

static void p2p_udp_pong(p2p_conn_t *conn, uint64_t nonce)
{
	uchar pkt[16];

	pack_ctrl(pkt, P2P_UDP_TYPE_PONG, nonce);
	udp_sendto(conn, pkt, 16);
}

bool p2p_udp_send(p2p_conn_t *conn, const char *cmd, const uchar *payload,
		  uint32_t plen)
{
	uint64_t msg_id, nonce;
	uint32_t offset, glen;
	uint16_t g, ngroups, k, n, idx;
	uchar *block, *base, **ptrs;
	uchar pkt[P2P_UDP_MAXPKT];
	int i;

	if (!conn || !cmd)
		return false;

	if (!strcmp(cmd, "ping") && plen == 8) {
		memcpy(&nonce, payload, 8);
		nonce = le64toh(nonce);
		p2p_udp_ping(conn, nonce);
		return true;
	}
	if (!strcmp(cmd, "pong") && plen == 8) {
		memcpy(&nonce, payload, 8);
		nonce = le64toh(nonce);
		p2p_udp_pong(conn, nonce);
		return true;
	}

	msg_id = ((uint64_t)rand() << 32) | rand();
	if (!plen) {
		ngroups = 1;
	} else {
		uint32_t per = (uint32_t)P2P_FEC_MAX_K * P2P_FEC_SHARD;

		ngroups = (uint16_t)((plen + per - 1) / per);
		if (!ngroups)
			ngroups = 1;
	}

	offset = 0;
	for (g = 0; g < ngroups; g++) {
		if (offset < plen)
			glen = plen - offset;
		else
			glen = 0;
		if (glen > (uint32_t)P2P_FEC_MAX_K * P2P_FEC_SHARD)
			glen = (uint32_t)P2P_FEC_MAX_K * P2P_FEC_SHARD;
		k = p2p_fec_k_for_bytes(glen);
		n = p2p_fec_n(k);

		block = ckzalloc((size_t)n * P2P_FEC_SHARD + 64);
		base = (uchar *)(((uintptr_t)block + 31) & ~(uintptr_t)31);
		ptrs = ckalloc(sizeof(uchar *) * n);
		for (i = 0; i < n; i++)
			ptrs[i] = base + (size_t)i * P2P_FEC_SHARD;

		if (!p2p_fec_encode(payload ? payload + offset : NULL, glen, k, n, ptrs)) {
			LOGNOTICE("UDP FEC encode failed for %s to peer %d", cmd, conn->peer);
			dealloc(ptrs);
			dealloc(block);
			return false;
		}

		for (idx = 0; idx < n; idx++) {
			size_t dlen = P2P_UDP_HDR + P2P_FEC_SHARD;

			memcpy(pkt, udp_magic, 4);
			pkt[4] = P2P_UDP_TYPE_MSG;
			pkt[5] = P2P_UDP_VER;
			pkt[6] = 0;
			pkt[7] = 0;
			pack_le64(pkt + 8, msg_id);
			memset(pkt + 16, 0, 12);
			strncpy((char *)(pkt + 16), cmd, 12);
			pack_le32(pkt + 28, plen);
			pack_le16(pkt + 32, g);
			pack_le16(pkt + 34, ngroups);
			pack_le16(pkt + 36, k);
			pack_le16(pkt + 38, n);
			pack_le16(pkt + 40, idx);
			pack_le16(pkt + 42, P2P_FEC_SHARD);
			memcpy(pkt + 44, ptrs[idx], P2P_FEC_SHARD);
			if (!udp_sendto(conn, pkt, dlen)) {
				dealloc(ptrs);
				dealloc(block);
				return false;
			}
		}
		dealloc(ptrs);
		dealloc(block);
		offset += glen;
	}
	p2p_mark_alive(conn);
	LOGINFO("UDP sent %s (%u bytes, %u groups) to peer %d", cmd, plen, ngroups,
		conn->peer);
	return true;
}

static void fec_group_free(struct fec_group *g)
{
	int i;

	if (!g)
		return;
	for (i = 0; i < P2P_FEC_MAX_N; i++)
		dealloc(g->shards[i]);
	free(g);
}

static void fec_msg_free(struct fec_msg *m)
{
	int i;

	if (!m)
		return;
	if (m->parts) {
		for (i = 0; i < m->ngroups; i++)
			dealloc(m->parts[i]);
		dealloc(m->parts);
	}
	dealloc(m->plens);
	dealloc(m->haveg);
	free(m);
}

static void fec_expire(tv_t *now)
{
	struct fec_group *g, *gtmp;
	struct fec_msg *m, *mtmp;

	DL_FOREACH_SAFE(fec_groups, g, gtmp) {
		if (tvdiff(now, &g->started) >= P2P_UDP_GROUP_EXPIRE) {
			DL_DELETE(fec_groups, g);
			fec_group_free(g);
		}
	}
	DL_FOREACH_SAFE(fec_msgs, m, mtmp) {
		if (tvdiff(now, &m->started) >= P2P_UDP_GROUP_EXPIRE) {
			DL_DELETE(fec_msgs, m);
			fec_msg_free(m);
		}
	}
}

static void dispatch_complete_msg(struct fec_msg *m)
{
	uint32_t tot = 0, off = 0;
	uchar *payload = NULL;
	int i;

	for (i = 0; i < m->ngroups; i++) {
		if (!m->haveg[i] || !m->parts[i])
			return;
		tot += m->plens[i];
	}
	if (tot != m->total_len) {
		LOGINFO("UDP FEC assembled length %u != %u", tot, m->total_len);
		return;
	}
	if (tot) {
		payload = ckalloc(tot);
		for (i = 0; i < m->ngroups; i++) {
			memcpy(payload + off, m->parts[i], m->plens[i]);
			off += m->plens[i];
		}
	}
	if (m->conn && m->conn->handshake_done)
		p2p_handle_msg(m->conn, m->cmd, payload, tot);
	else
		dealloc(payload);
}

static void fec_take_group(struct fec_group *g, uchar *data, uint32_t glen)
{
	struct fec_msg *m, *found = NULL;
	uint32_t per = (uint32_t)P2P_FEC_MAX_K * P2P_FEC_SHARD;
	uint32_t expect;
	tv_t now;

	tv_monotonic(&now);
	DL_FOREACH(fec_msgs, m) {
		if (m->msg_id == g->msg_id && !strcmp(m->ip, g->ip)) {
			found = m;
			break;
		}
	}
	if (!found) {
		found = ckzalloc(sizeof(*found));
		found->msg_id = g->msg_id;
		found->ngroups = g->ngroups;
		found->total_len = g->total_len;
		memcpy(found->cmd, g->cmd, 12);
		found->cmd[12] = 0;
		snprintf(found->ip, sizeof(found->ip), "%s", g->ip);
		found->conn = g->conn;
		found->parts = ckzalloc(sizeof(uchar *) * g->ngroups);
		found->plens = ckzalloc(sizeof(uint32_t) * g->ngroups);
		found->haveg = ckzalloc(sizeof(bool) * g->ngroups);
		copy_tv(&found->started, &now);
		DL_APPEND(fec_msgs, found);
	}
	if (g->group >= found->ngroups)
		return;
	if (g->group + 1 == found->ngroups)
		expect = found->total_len - g->group * per;
	else
		expect = per;
	if (glen > expect)
		glen = expect;
	if (!found->haveg[g->group]) {
		found->parts[g->group] = data;
		found->plens[g->group] = glen;
		found->haveg[g->group] = true;
		found->got++;
		data = NULL;
	}
	dealloc(data);
	if (found->got >= found->ngroups) {
		dispatch_complete_msg(found);
		DL_DELETE(fec_msgs, found);
		fec_msg_free(found);
	}
}

static void handle_msg_shard(p2p_conn_t *conn, const char *ip, const uchar *pkt,
			     size_t len)
{
	struct fec_group *g, *found = NULL;
	uint64_t msg_id;
	uint16_t group, ngroups, k, n, idx, shard_len;
	uint32_t total_len, glen;
	char cmd[13];
	uchar *out;
	tv_t now;
	int i;

	if (len < P2P_UDP_HDR)
		return;
	msg_id = unpack_le64(pkt + 8);
	memcpy(cmd, pkt + 16, 12);
	cmd[12] = 0;
	total_len = unpack_le32(pkt + 28);
	group = unpack_le16(pkt + 32);
	ngroups = unpack_le16(pkt + 34);
	k = unpack_le16(pkt + 36);
	n = unpack_le16(pkt + 38);
	idx = unpack_le16(pkt + 40);
	shard_len = unpack_le16(pkt + 42);
	if (!k || k > P2P_FEC_MAX_K || n <= k || n > P2P_FEC_MAX_N)
		return;
	if (idx >= n || shard_len != P2P_FEC_SHARD)
		return;
	if (len < (size_t)P2P_UDP_HDR + shard_len)
		return;
	if (!ngroups || group >= ngroups)
		return;

	tv_monotonic(&now);
	fec_expire(&now);

	DL_FOREACH(fec_groups, g) {
		if (g->msg_id == msg_id && g->group == group && !strcmp(g->ip, ip)) {
			found = g;
			break;
		}
	}
	if (!found) {
		found = ckzalloc(sizeof(*found));
		found->msg_id = msg_id;
		found->group = group;
		found->ngroups = ngroups;
		found->k = k;
		found->n = n;
		found->total_len = total_len;
		memcpy(found->cmd, cmd, 12);
		found->cmd[12] = 0;
		snprintf(found->ip, sizeof(found->ip), "%s", ip);
		found->conn = conn;
		copy_tv(&found->started, &now);
		DL_APPEND(fec_groups, found);
	}
	if (found->have[idx])
		return;
	found->shards[found->got] = ckalloc(P2P_FEC_SHARD);
	memcpy(found->shards[found->got], pkt + P2P_UDP_HDR, P2P_FEC_SHARD);
	found->idxs[found->got] = idx;
	found->have[idx] = true;
	found->got++;

	if (found->got < found->k)
		return;

	if (group + 1 == ngroups)
		glen = total_len - (uint32_t)group * (uint32_t)P2P_FEC_MAX_K * P2P_FEC_SHARD;
	else
		glen = (uint32_t)found->k * P2P_FEC_SHARD;
	if (glen > (uint32_t)found->k * P2P_FEC_SHARD)
		glen = (uint32_t)found->k * P2P_FEC_SHARD;

	out = ckalloc(glen ? glen : 1);
	if (!p2p_fec_decode(found->shards, found->idxs, found->got, found->k,
			    found->n, out, glen)) {
		LOGINFO("UDP FEC decode failed for %s from %s", cmd, ip);
		dealloc(out);
		return;
	}
	DL_DELETE(fec_groups, found);
	fec_take_group(found, out, glen);
	for (i = 0; i < P2P_FEC_MAX_N; i++)
		found->shards[i] = NULL;
	fec_group_free(found);
}

static void handle_ctrl(p2p_conn_t *conn, const char *ip,
			const struct sockaddr *sa, socklen_t slen,
			const uchar *pkt, size_t len)
{
	uint8_t type = pkt[4];
	uint64_t nonce;
	p2p_conn_t *c;

	if (len < 16)
		return;
	nonce = unpack_le64(pkt + 8);

	if (type == P2P_UDP_TYPE_HELLO) {
		c = conn;
		if (!c)
			c = ckp2p_udp_bind_peer(ip, sa, slen);
		if (!c)
			return;
		send_helloack(c, nonce);
		if (!c->handshake_done) {
			c->udp = true;
			c->ckp2p_peer = true;
			c->handshake_done = true;
			c->udp_hello_acked = true;
			ckp2p_client_drop_tcp(ip, c);
			ckp2p_client_set(ip, P2P_XPORT_UDP, c);
			LOGNOTICE("UDP HELLO from %s peer %d", ip, c->peer);
		}
		return;
	}
	if (type == P2P_UDP_TYPE_HELLOACK) {
		c = conn;
		if (!c)
			c = ckp2p_client_find(ip);
		if (!c)
			return;
		if (c->udp_hello_nonce && c->udp_hello_nonce != nonce) {
			LOGDEBUG("UDP HELLOACK nonce mismatch from %s", ip);
			return;
		}
		c->udp = true;
		c->ckp2p_peer = true;
		c->handshake_done = true;
		c->udp_hello_acked = true;
		if (sa && slen && slen <= sizeof(c->udp_dst)) {
			memcpy(&c->udp_dst, sa, slen);
			c->udp_dstlen = slen;
		}
		ckp2p_client_drop_tcp(ip, c);
		ckp2p_client_set(ip, P2P_XPORT_UDP, c);
		LOGNOTICE("UDP HELLOACK from %s peer %d", ip, c->peer);
		return;
	}
	if (!conn)
		return;
	if (type == P2P_UDP_TYPE_PING) {
		p2p_udp_pong(conn, nonce);
		p2p_mark_alive(conn);
		return;
	}
	if (type == P2P_UDP_TYPE_PONG)
		p2p_mark_alive(conn);
}

void *p2p_udp_receiver(void __maybe_unused *arg)
{
	uchar pkt[P2P_UDP_MAXPKT];
	char ip[INET6_ADDRSTRLEN];

	pthread_detach(pthread_self());
	rename_proc("ckp2pudp");

	while (42) {
		struct sockaddr_storage ss;
		socklen_t slen = sizeof(ss);
		p2p_conn_t *conn;
		ssize_t n;

		if (udp_fd < 0)
			break;
		n = recvfrom(udp_fd, pkt, sizeof(pkt), 0, (struct sockaddr *)&ss, &slen);
		if (n <= 0) {
			if (n < 0 && errno != EINTR)
				LOGDEBUG("UDP recvfrom: %s", strerror(errno));
			continue;
		}
		if (n < 8)
			continue;
		if (memcmp(pkt, udp_magic, 4))
			continue;
		if (pkt[5] != P2P_UDP_VER)
			continue;
		p2p_udp_canon_ip((struct sockaddr *)&ss, ip, sizeof(ip));
		conn = ckp2p_client_find(ip);
		if (pkt[4] == P2P_UDP_TYPE_MSG) {
			if (!conn || !conn->handshake_done)
				continue;
			handle_msg_shard(conn, ip, pkt, (size_t)n);
		} else {
			handle_ctrl(conn, ip, (struct sockaddr *)&ss, slen, pkt,
				    (size_t)n);
		}
	}
	return NULL;
}
