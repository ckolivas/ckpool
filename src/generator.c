/*
 * Copyright 2014-2017,2023,2026 Con Kolivas
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 3 of the License, or (at your option)
 * any later version.  See COPYING for more details.
 */

#include "config.h"

#include <sys/epoll.h>
#include <sys/socket.h>
#include <math.h>
#include <string.h>
#include <unistd.h>

#include "ckpool.h"
#include "libckpool.h"
#include "generator.h"
#include "stratifier.h"
#include "bitcoin.h"
#include "uthash.h"
#include "utlist.h"

struct notify_instance {
	/* Hash table data */
	UT_hash_handle hh;
	int64_t id64;

	char prevhash[68];
	yyjson_mut_doc *jobid;
	char *coinbase1;
	char *coinbase2;
	int coinb1len;
	int merkles;
	char merklehash[16][68];
	char nbit[12];
	char ntime[12];
	char bbversion[12];
	bool clean;

	time_t notify_time;
};

typedef struct notify_instance notify_instance_t;

typedef struct proxy_instance proxy_instance_t;

struct share_msg {
	UT_hash_handle hh;
	int64_t id64; // Our own id for submitting upstream

	int64_t client_id;
	time_t submit_time;
	double diff;
};

typedef struct share_msg share_msg_t;

struct stratum_msg {
	struct stratum_msg *next;
	struct stratum_msg *prev;

	yyjson_mut_doc *doc;
	int64_t client_id;
};

typedef struct stratum_msg stratum_msg_t;

struct pass_msg {
	proxy_instance_t *proxy;
	connsock_t *cs;
	char *msg;
};

typedef struct pass_msg pass_msg_t;
typedef struct cs_msg cs_msg_t;

/* Statuses of various proxy states - connect, subscribe and auth */
enum proxy_stat {
	STATUS_INIT = 0,
	STATUS_SUCCESS,
	STATUS_FAIL
};

static const char *proxy_status[] = {
	"Initial",
	"Success",
	"Failed"
};

/* Per proxied pool instance data */
struct proxy_instance {
	UT_hash_handle hh; /* Proxy list */
	UT_hash_handle sh; /* Subproxy list */
	proxy_instance_t *next; /* For dead proxy list */
	proxy_instance_t *prev; /* For dead proxy list */

	connsock_t cs;
	bool passthrough;
	bool node;
	int id; /* Proxy server id*/
	int subid; /* Subproxy id */
	int userid; /* User id if this proxy is bound to a user */

	char *baseurl;
	char *url;
	char *auth;
	char *pass;

	char *enonce1;
	char *enonce1bin;
	int nonce1len;
	int nonce2len;

	tv_t last_message;

	double diff;
	double diff_accepted;
	double diff_rejected;
	double total_accepted; /* Used only by parent proxy structures */
	double total_rejected; /* "" */
	tv_t last_share;

	/* Diff shares per second for 1/5/60... minute rolling averages */
	double dsps1;
	double dsps5;
	double dsps60;
	double dsps360;
	double dsps1440;
	tv_t last_decay;

	/* Total diff shares per second for all subproxies */
	double tdsps1; /* Used only by parent proxy structures */
	double tdsps5; /* "" */
	double tdsps60; /* "" */
	double tdsps360; /* "" */
	double tdsps1440; /* "" */
	tv_t total_last_decay;

	bool no_params; /* Doesn't want any parameters on subscribe */

	bool global;	/* Part of the global list of proxies */
	bool disabled; /* Subproxy no longer to be used */
	bool reconnect; /* We need to drop and reconnect */
	bool reconnecting; /* Testing of parent in progress */
	int64_t recruit; /* No of recruiting requests in progress */
	bool alive;
	bool authorised;

	/* Which of STATUS_* states are these in */
	enum proxy_stat connect_status;
	enum proxy_stat subscribe_status;
	enum proxy_stat auth_status;

	/* Back off from retrying if we fail one of the above */
	int backoff;

	 /* Are we in the middle of a blocked write of this message? */
	cs_msg_t *sending;

	pthread_t pth_precv;

	ckmsgq_t *passsends;	// passthrough sends

	char_entry_t *recvd_lines; /* Linked list of unprocessed messages */

	int epfd; /* Epoll fd used by the parent proxy */

	mutex_t proxy_lock; /* Lock protecting hashlist of proxies */
	proxy_instance_t *parent; /* Parent proxy of subproxies */
	proxy_instance_t *subproxies; /* Hashlist of subproxies of this proxy */
	int64_t clients_per_proxy; /* Max number of clients of this proxy */
	int subproxy_count; /* Number of subproxies */
};

/* Private data for the generator */
struct generator_data {
	mutex_t lock; /* Lock protecting linked lists */
	proxy_instance_t *proxies; /* Hash list of all proxies */
	proxy_instance_t *dead_proxies; /* Disabled proxies */
	int proxies_generated;
	int subproxies_generated;

	int64_t proxy_notify_id;	// Globally increasing notify id
	pthread_t pth_uprecv;	// User proxy receive thread
	pthread_t pth_psend;	// Combined proxy send thread

	mutex_t psend_lock;	// Lock associated with conditional below
	pthread_cond_t psend_cond;

	stratum_msg_t *psends;
	int psends_generated;

	mutex_t notify_lock;
	notify_instance_t *notify_instances;

	mutex_t share_lock;
	share_msg_t *shares;
	int64_t share_id;

	server_instance_t *current_si; // Current server instance

	proxy_instance_t *current_proxy;
};

typedef struct generator_data gdata_t;

/* Use a temporary fd when testing server_alive to avoid races on cs->fd */
static bool server_alive(server_instance_t *si, bool pinging)
{
	char *userpass = NULL;
	bool ret = false;
	connsock_t *cs;
	gbtbase_t gbt;
	int fd;

	if (si->alive)
		return true;
	cs = &si->cs;
	if (!extract_sockaddr(si->url, &cs->url, &cs->port)) {
		LOGWARNING("Failed to extract address from %s", si->url);
		return ret;
	}
	userpass = strdup(si->auth);
	realloc_strcat(&userpass, ":");
	realloc_strcat(&userpass, si->pass);
	dealloc(cs->auth);
	cs->auth = http_base64(userpass);
	if (!cs->auth) {
		LOGWARNING("Failed to create base64 auth from %s", userpass);
		dealloc(userpass);
		return ret;
	}
	dealloc(userpass);

	fd = connect_socket(cs->url, cs->port);
	if (fd < 0) {
		if (!pinging)
			LOGWARNING("Failed to connect socket to %s:%s !", cs->url, cs->port);
		return ret;
	}

	/* Test we can connect, authorise and get a block template */
	if (!gen_gbtbase(cs, &gbt)) {
		if (!pinging) {
			LOGINFO("Failed to get test block template from %s:%s!",
				cs->url, cs->port);
		}
		goto out;
	}
	clear_gbtbase(&gbt);
	if (unlikely(ckpool.btcsolo && !ckpool.btcaddress)) {
		/* If no btcaddress is specified in solobtc mode, choose one of
		 * the donation addresses from mainnet, testnet, or regtest for
		 * coinbase validation later on, although it will not be used
		 * for mining. */
		if (validate_address(cs, ckpool.donaddress, &ckpool.script, &ckpool.segwit))
			ckpool.btcaddress = ckpool.donaddress;
		else if (validate_address(cs, ckpool.tndonaddress, &ckpool.script, &ckpool.segwit))
			ckpool.btcaddress = ckpool.tndonaddress;
		else if (validate_address(cs, ckpool.rtdonaddress, &ckpool.script, &ckpool.segwit))
			ckpool.btcaddress = ckpool.rtdonaddress;
	}

	if (!ckpool.node && !validate_address(cs, ckpool.btcaddress, &ckpool.script, &ckpool.segwit)) {
		LOGWARNING("Invalid btcaddress: %s !", ckpool.btcaddress);
		goto out;
	}
	si->alive = cs->alive = ret = true;
	LOGWARNING("Server alive: %s:%s", cs->url, cs->port);
out:
	/* Close the file handle */
	close(fd);
	return ret;
}

/* Find the highest priority server alive and return it */
static server_instance_t *live_server(gdata_t *gdata)
{
	server_instance_t *alive = NULL;
	connsock_t *cs;
	int i;

	LOGDEBUG("Attempting to connect to bitcoind");
retry:
	/* First find a server that is already flagged alive if possible
	 * without blocking on server_alive() */
	for (i = 0; i < ckpool.btcds; i++) {
		server_instance_t *si = ckpool.servers[i];
		cs = &si->cs;

		if (si->alive) {
			alive = si;
			goto living;
		}
	}

	/* No servers flagged alive, try to connect to them blocking */
	for (i = 0; i < ckpool.btcds; i++) {
		server_instance_t *si = ckpool.servers[i];

		if (server_alive(si, false)) {
			alive = si;
			goto living;
		}
	}
	LOGWARNING("CRITICAL: No bitcoinds active!");
	sleep(5);
	goto retry;
living:
	gdata->current_si = alive;
	cs = &alive->cs;
	LOGINFO("Connected to live server %s:%s", cs->url, cs->port);
	send_proc(ckpool.connector, alive ? "accept" : "reject");
	return alive;
}

static void kill_server(server_instance_t *si)
{
	connsock_t *cs;

	if (!si) // This shouldn't happen
		return;

	LOGNOTICE("Killing server");
	cs = &si->cs;
	Close(cs->fd);
	empty_buffer(cs);
	dealloc(cs->url);
	dealloc(cs->port);
	dealloc(cs->auth);
}

static void clear_unix_msg(unix_msg_t **umsg)
{
	if (*umsg) {
		Close((*umsg)->sockd);
		free((*umsg)->buf);
		free(*umsg);
		*umsg = NULL;
	}
}

bool generator_submitblock(const char *buf)
{
	gdata_t *gdata = ckpool.gdata;
	server_instance_t *si;
	bool warn = false;
	connsock_t *cs;

	while (unlikely(!(si = gdata->current_si))) {
		if (!warn)
			LOGWARNING("No live current server in generator_blocksubmit! Resubmitting indefinitely!");
		warn = true;
		cksleep_ms(10);
	}
	cs = &si->cs;
	LOGNOTICE("Submitting block data!");
	return submit_block(cs, buf);
}

void generator_preciousblock(const char *hash)
{
	gdata_t *gdata = ckpool.gdata;
	server_instance_t *si;
	connsock_t *cs;

	if (unlikely(!(si = gdata->current_si))) {
		LOGWARNING("No live current server in generator_get_blockhash");
		return;
	}
	cs = &si->cs;
	precious_block(cs, hash);
}

bool generator_get_blockhash(int height, char *hash)
{
	gdata_t *gdata = ckpool.gdata;
	server_instance_t *si;
	connsock_t *cs;

	if (unlikely(!(si = gdata->current_si))) {
		LOGWARNING("No live current server in generator_get_blockhash");
		return false;
	}
	cs = &si->cs;
	return get_blockhash(cs, height, hash);
}

static void gen_loop(proc_instance_t *pi)
{
	server_instance_t *si = NULL, *old_si;
	unix_msg_t *umsg = NULL;
	char *buf = NULL;
	connsock_t *cs;
	gbtbase_t gbt;
	char hash[68];

reconnect:
	clear_unix_msg(&umsg);
	old_si = si;
	si = live_server(ckpool.gdata);
	if (!si)
		goto out;
	if (unlikely(!ckpool.generator_ready)) {
		ckpool.generator_ready = true;
		LOGWARNING("%s generator ready", ckpool.name);
	}

	cs = &si->cs;
	if (!old_si)
		LOGWARNING("Connected to bitcoind: %s:%s", cs->url, cs->port);
	else if (si != old_si)
		LOGWARNING("Failed over to bitcoind: %s:%s", cs->url, cs->port);

retry:
	clear_unix_msg(&umsg);

	do {
		umsg = get_unix_msg(pi);
	} while (!umsg);

	if (unlikely(!si->alive)) {
		LOGWARNING("%s:%s Bitcoind socket invalidated, will attempt failover", cs->url, cs->port);
		goto reconnect;
	}

	buf = umsg->buf;
	LOGDEBUG("Generator received request: %s", buf);
	if (cmdmatch(buf, "getbase")) {
		if (!gen_gbtbase(cs, &gbt)) {
			LOGWARNING("Failed to get block template from %s:%s",
				   cs->url, cs->port);
			si->alive = cs->alive = false;
			send_unix_msg(umsg->sockd, "Failed");
			goto reconnect;
		} else {
			char *s = yyjson_write(gbt.gbtdoc, 0, NULL);

			send_unix_msg(umsg->sockd, s);
			free(s);
			clear_gbtbase(&gbt);
		}
	} else if (cmdmatch(buf, "getbest")) {
		if (si->notify)
			send_unix_msg(umsg->sockd, "notify");
		else if (!get_bestblockhash(cs, hash)) {
			LOGINFO("No best block hash support from %s:%s",
				cs->url, cs->port);
			si->alive = cs->alive = false;
			send_unix_msg(umsg->sockd, "failed");
		} else {
			send_unix_msg(umsg->sockd, hash);
		}
	} else if (cmdmatch(buf, "getlast")) {
		int height;

		if (si->notify)
			send_unix_msg(umsg->sockd, "notify");
		else if ((height = get_blockcount(cs)) == -1) {
			si->alive = cs->alive = false;
			send_unix_msg(umsg->sockd,  "failed");
			goto reconnect;
		} else {
			LOGDEBUG("Height: %d", height);
			if (!get_blockhash(cs, height, hash)) {
				si->alive = cs->alive = false;
				send_unix_msg(umsg->sockd, "failed");
				goto reconnect;
			} else {
				send_unix_msg(umsg->sockd, hash);
				LOGDEBUG("Hash: %s", hash);
			}
		}
	} else if (cmdmatch(buf, "submitblock:")) {
		char blockmsg[80];
		bool ret;

		LOGNOTICE("Submitting block data!");
		ret = submit_block(cs, buf + 12 + 64 + 1);
		memset(buf + 12 + 64, 0, 1);
		sprintf(blockmsg, "%sblock:%s", ret ? "" : "no", buf + 12);
		send_proc(ckpool.stratifier, blockmsg);
	} else if (cmdmatch(buf, "reconnect")) {
		goto reconnect;
	} else if (cmdmatch(buf, "loglevel")) {
		sscanf(buf, "loglevel=%d", &ckpool.loglevel);
	} else if (cmdmatch(buf, "ping")) {
		LOGDEBUG("Generator received ping request");
		send_unix_msg(umsg->sockd, "pong");
	}
	goto retry;

out:
	kill_server(si);
}

static bool connect_proxy(connsock_t *cs, proxy_instance_t *proxy)
{
	if (cs->fd > 0) {
		epoll_ctl(proxy->epfd, EPOLL_CTL_DEL, cs->fd, NULL);
		Close(cs->fd);
	}
	cs->fd = connect_socket(cs->url, cs->port);
	if (cs->fd < 0) {
		LOGINFO("Failed to connect socket to %s:%s in connect_proxy",
			cs->url, cs->port);
		return false;
	}
	keep_sockalive(cs->fd);
	if (!ckpool.passthrough) {
		struct epoll_event event;

		event.events = EPOLLIN | EPOLLRDHUP;
		event.data.ptr = proxy;
		/* Add this connsock_t to the epoll list */
		if (unlikely(epoll_ctl(proxy->epfd, EPOLL_CTL_ADD, cs->fd, &event) == -1)) {
			LOGERR("Failed to add fd %d to epfd %d to epoll_ctl in proxy_alive",
				cs->fd, proxy->epfd);
			return false;
		}
	} else {
		/* We want large send/recv buffers on passthroughs */
		if (!ckpool.rmem_warn)
			cs->rcvbufsiz = set_recvbufsize(cs->fd, 1048576);
		if (!ckpool.wmem_warn)
			cs->sendbufsiz = set_sendbufsize(cs->fd, 1048576);
	}
	return true;
}

/* For some reason notify is buried at various different array depths so use
 * a reentrant function to try and find it. */
static yyjson_val *find_notify(yyjson_val *val)
{
	yyjson_val *ret = NULL;
	int arr_size, i;
	const char *entry;

	if (!yyjson_is_arr(val))
		return NULL;
	arr_size = yyjson_arr_size(val);
	entry = yyjson_get_str(yyjson_arr_get(val, 0));
	if (cmdmatch(entry, "mining.notify"))
		return val;
	for (i = 0; i < arr_size; i++) {
		yyjson_val *arr_val;

		arr_val = yyjson_arr_get(val, i);
		ret = find_notify(arr_val);
		if (ret)
			break;
	}
	return ret;
}

/* Get stored line in the proxy linked list of messages if any exist or NULL */
static char *cached_proxy_line(proxy_instance_t *proxi)
{
	char *buf = NULL;

	if (proxi->recvd_lines) {
		char_entry_t *char_t = proxi->recvd_lines;

		DL_DELETE(proxi->recvd_lines, char_t);
		buf = char_t->buf;
		free(char_t);
	}
	return buf;
}

/* Get next line in the proxy linked list of messages or a new line from the
 * connsock if there are none. */
static char *next_proxy_line(connsock_t *cs, proxy_instance_t *proxi)
{
	char *buf = cached_proxy_line(proxi);
	float timeout = 10;

	if (!buf && read_socket_line(cs, &timeout) > 0)
		buf = strdup(cs->buf);
	return buf;
}

/* For appending a line to the proxy recv list */
static void append_proxy_line(proxy_instance_t *proxi, const char *buf)
{
	char_entry_t *char_t = ckalloc(sizeof(char_entry_t));
	char_t->buf = strdup(buf);
	DL_APPEND(proxi->recvd_lines, char_t);
}

/* Get a new line from the connsock and return a copy of it */
static char *new_proxy_line(connsock_t *cs)
{
	float timeout = 10;
	char *buf = NULL;

	if (read_socket_line(cs, &timeout) < 1)
		goto out;
	buf = strdup(cs->buf);
out:
	return buf;
}

static inline bool parent_proxy(const proxy_instance_t *proxy)
{
	return (proxy->parent == proxy);
}

static void recruit_subproxies(proxy_instance_t *proxi, const int recruits);

static bool parse_subscribe(connsock_t *cs, proxy_instance_t *proxi)
{
	yyjson_val *res_val, *notify_val, *tmp;
	yyjson_doc *val = NULL;
	bool parsed, ret = false;
	int retries = 0, size;
	const char *string;
	char *buf, *old;

retry:
	parsed = true;
	if (!(buf = new_proxy_line(cs))) {
		LOGNOTICE("Proxy %d:%d %s failed to receive line in parse_subscribe",
			   proxi->id, proxi->subid, proxi->url);
		goto out;
	}
	LOGDEBUG("parse_subscribe received %s", buf);
	/* Ignore err_val here stored in &tmp */
	val = yyjson_msg_result(buf, &res_val, &tmp);
	if (!val || !res_val) {
		LOGINFO("Failed to get a json result in parse_subscribe, got: %s", buf);
		parsed = false;
	}
	if (!yyjson_is_arr(res_val)) {
		LOGINFO("Result in parse_subscribe not an array");
		parsed = false;
	}
	size = yyjson_arr_size(res_val);
	if (size < 3) {
		LOGINFO("Result in parse_subscribe array too small");
		parsed = false;
	}
	notify_val = find_notify(res_val);
	if (!notify_val) {
		LOGINFO("Failed to find notify in parse_subscribe");
		parsed = false;
	}
	if (!parsed) {
		if (++retries < 3) {
			/* We don't want this response so put it on the proxy
			 * recvd list to be parsed later */
			append_proxy_line(proxi, buf);
			buf = NULL;
			if (val) {
				yyjson_doc_free(val);
				val = NULL;
			}
			goto retry;
		}
		LOGNOTICE("Proxy %d:%d %s failed to parse subscribe response in parse_subscribe",
			  proxi->id, proxi->subid, proxi->url);
		goto out;
	}

	tmp = yyjson_arr_get(res_val, 1);
	if (!tmp || !yyjson_is_str(tmp)) {
		LOGWARNING("Failed to parse enonce1 in parse_subscribe");
		goto out;
	}
	string = yyjson_get_str(tmp);
	old = proxi->enonce1;
	proxi->enonce1 = strdup(string);
	free(old);
	proxi->nonce1len = strlen(proxi->enonce1) / 2;
	if (proxi->nonce1len > 15) {
		LOGWARNING("Nonce1 too long at %d", proxi->nonce1len);
		goto out;
	}
	old = proxi->enonce1bin;
	proxi->enonce1bin = ckalloc(proxi->nonce1len);
	free(old);
	hex2bin(proxi->enonce1bin, proxi->enonce1, proxi->nonce1len);
	tmp = yyjson_arr_get(res_val, 2);
	if (!tmp || !yyjson_is_int(tmp)) {
		LOGWARNING("Failed to parse nonce2len in parse_subscribe");
		goto out;
	}
	size = yyjson_get_sint(tmp);
	if (size < 1 || size > 8) {
		LOGWARNING("Invalid nonce2len %d in parse_subscribe", size);
		goto out;
	}
	if (size < 3) {
		if (!proxi->subid) {
			LOGWARNING("Proxy %d %s Nonce2 length %d too small for fast miners",
				   proxi->id, proxi->url, size);
		} else {
			LOGNOTICE("Proxy %d:%d Nonce2 length %d too small for fast miners",
				   proxi->id, proxi->subid, size);
		}
	}
	proxi->nonce2len = size;
	proxi->clients_per_proxy = 1ll << ((size - 3) * 8);

	LOGNOTICE("Found notify for new proxy %d:%d with enonce %s nonce2len %d", proxi->id,
		proxi->subid, proxi->enonce1, proxi->nonce2len);
	ret = true;

out:
	if (val)
		yyjson_doc_free(val);
	free(buf);
	return ret;
}

/* cs semaphore must be held */
static bool subscribe_stratum(connsock_t *cs, proxy_instance_t *proxi)
{
	yyjson_mut_doc *req;
	bool ret = false;

retry:
	/* Attempt to connect with the client description g*/
	if (!proxi->no_params) {
		req = yyjson_mut_pack("{s:i,s:s,s:[s]}",
				      "id", 0,
				      "method", "mining.subscribe",
				      "params", PACKAGE"/"VERSION);
	/* Then try without any parameters */
	} else {
		req = yyjson_mut_pack("{s:i,s:s,s:[]}",
				      "id", 0,
				      "method", "mining.subscribe",
				      "params");
	}
	ret = send_yyjson_msg(cs, req);
	yyjson_mut_doc_free(req);
	if (!ret) {
		LOGNOTICE("Proxy %d:%d %s failed to send message in subscribe_stratum",
			   proxi->id, proxi->subid, proxi->url);
		goto out;
	}
	ret = parse_subscribe(cs, proxi);
	if (ret)
		goto out;

	if (proxi->no_params) {
		LOGNOTICE("Proxy %d:%d %s failed all subscription options in subscribe_stratum",
			   proxi->id, proxi->subid, proxi->url);
		goto out;
	}
	LOGINFO("Proxy %d:%d %s failed connecting with parameters in subscribe_stratum, retrying without",
		proxi->id, proxi->subid, proxi->url);
	proxi->no_params = true;
	ret = connect_proxy(cs, proxi);
	if (!ret) {
		LOGNOTICE("Proxy %d:%d %s failed to reconnect in subscribe_stratum",
			   proxi->id, proxi->subid, proxi->url);
		goto out;
	}
	goto retry;

out:
	if (!ret && cs->fd > 0) {
		epoll_ctl(proxi->epfd, EPOLL_CTL_DEL, cs->fd, NULL);
		Close(cs->fd);
	}
	return ret;
}

/* cs semaphore must be held */
static bool passthrough_stratum(connsock_t *cs, proxy_instance_t *proxi)
{
	yyjson_val *res_val, *err_val;
	yyjson_doc *val = NULL;
	bool res, ret = false;
	yyjson_mut_doc *req;
	float timeout = 10;

	req = yyjson_mut_pack("{ss,s[s]}",
			      "method", "mining.passthrough",
			      "params", PACKAGE"/"VERSION);
	res = send_yyjson_msg(cs, req);
	yyjson_mut_doc_free(req);
	if (!res) {
		LOGWARNING("Failed to send message in passthrough_stratum");
		goto out;
	}
	if (read_socket_line(cs, &timeout) < 1) {
		LOGWARNING("Failed to receive line in passthrough_stratum");
		goto out;
	}
	/* Ignore err_val here since we should always get a result from an
	 * upstream passthrough server */
	val = yyjson_msg_result(cs->buf, &res_val, &err_val);
	if (!val || !res_val) {
		LOGWARNING("Failed to get a json result in passthrough_stratum, got: %s",
			   cs->buf);
		goto out;
	}
	ret = yyjson_is_true(res_val);
	if (!ret) {
		LOGWARNING("Denied passthrough for stratum");
		goto out;
	}
	proxi->passthrough = true;
out:
	if (val)
		yyjson_doc_free(val);
	if (!ret)
		Close(cs->fd);
	return ret;
}

/* cs semaphore must be held */
static bool node_stratum(connsock_t *cs, proxy_instance_t *proxi)
{
	yyjson_val *res_val, *err_val;
	yyjson_doc *val = NULL;
	bool res, ret = false;
	yyjson_mut_doc *req;
	float timeout = 10;

	req = yyjson_mut_pack("{ss,s[s]}",
			      "method", "mining.node",
			      "params", PACKAGE"/"VERSION);

	res = send_yyjson_msg(cs, req);
	yyjson_mut_doc_free(req);
	if (!res) {
		LOGWARNING("Failed to send message in node_stratum");
		goto out;
	}
	if (read_socket_line(cs, &timeout) < 1) {
		LOGWARNING("Failed to receive line in node_stratum");
		goto out;
	}
	/* Ignore err_val here since we should always get a result from an
	 * upstream server */
	val = yyjson_msg_result(cs->buf, &res_val, &err_val);
	if (!val || !res_val) {
		LOGWARNING("Failed to get a json result in node_stratum, got: %s",
			   cs->buf);
		goto out;
	}
	ret = yyjson_is_true(res_val);
	if (!ret) {
		LOGWARNING("Denied node setup for stratum");
		goto out;
	}
	proxi->node = true;
out:
	if (val)
		yyjson_doc_free(val);
	if (!ret)
		Close(cs->fd);
	return ret;
}

static void send_notify(proxy_instance_t *proxi, notify_instance_t *ni);

static void reconnect_generator(void)
{
	send_proc(ckpool.generator, "reconnect");
}

struct genwork *generator_getbase(void)
{
	gdata_t *gdata = ckpool.gdata;
	gbtbase_t *gbt = NULL;
	server_instance_t *si;
	connsock_t *cs;

	/* Use temporary variables to prevent deref while accessing */
	si = gdata->current_si;
	if (unlikely(!si)) {
		LOGWARNING("No live current server in generator_genbase");
		goto out;
	}
	cs = &si->cs;
	gbt = ckzalloc(sizeof(gbtbase_t));
	if (unlikely(!gen_gbtbase(cs, gbt))) {
		LOGWARNING("Failed to get block template from %s:%s", cs->url, cs->port);
		si->alive = cs->alive = false;
		reconnect_generator();
		dealloc(gbt);
	}
out:
	return gbt;
}

int generator_getbest(char *hash)
{
	gdata_t *gdata = ckpool.gdata;
	int ret = GETBEST_FAILED;
	server_instance_t *si;
	connsock_t *cs;

	si = gdata->current_si;
	if (unlikely(!si)) {
		LOGWARNING("No live current server in generator_getbest");
		goto out;
	}
	if (si->notify) {
		ret = GETBEST_NOTIFY;
		goto out;
	}
	cs = &si->cs;
	if (unlikely(!get_bestblockhash(cs, hash))) {
		LOGWARNING("Failed to get best block hash from %s:%s", cs->url, cs->port);
		goto out;
	}
	ret = GETBEST_SUCCESS;
out:
	return ret;
}

bool generator_checkaddr(const char *addr, bool *script, bool *segwit)
{
	gdata_t *gdata = ckpool.gdata;
	server_instance_t *si;
	int ret = false;
	connsock_t *cs;

	si = gdata->current_si;
	if (unlikely(!si)) {
		LOGWARNING("No live current server in generator_checkaddr");
		goto out;
	}
	cs = &si->cs;
	ret = validate_address(cs, addr, script, segwit);
out:
	return ret;
}

char *generator_checktxn(const char *txn)
{
	yyjson_doc *doc;
	gdata_t *gdata = ckpool.gdata;
	server_instance_t *si;
	char *ret = NULL;
	connsock_t *cs;

	si = gdata->current_si;
	if (unlikely(!si)) {
		LOGWARNING("No live current server in generator_checkaddr");
		goto out;
	}
	cs = &si->cs;
	doc = validate_txn(cs, txn);
	if (!doc) {
		LOGWARNING("Invalid response to generator_checkaddr");
		goto out;
	}
	ret = yyjson_write(doc, 0, NULL);
	yyjson_doc_free(doc);
out:
	return ret;
}

char *generator_get_txn(const char *hash)
{
	gdata_t *gdata = ckpool.gdata;
	server_instance_t *si;
	char *ret = NULL;
	connsock_t *cs;

	si = gdata->current_si;
	if (unlikely(!si)) {
		LOGWARNING("No live current server in generator_get_txn");
		goto out;
	}
	cs = &si->cs;
	ret = get_txn(cs, hash);
out:
	return ret;
}

static bool parse_notify(proxy_instance_t *proxi, yyjson_val *val)
{
	const char *prev_hash, *bbversion, *nbit, *ntime, *string;
	yyjson_mut_doc *job_id = NULL;
	gdata_t *gdata = ckpool.gdata;
	char *coinbase1 = NULL, *coinbase2 = NULL;
	const char *jobidbuf;
	bool clean, ret = false;
	notify_instance_t *ni;
	yyjson_val *arr, *jid;
	int merkles, i;

	arr = yyjson_arr_get(val, 4);
	if (!arr || !yyjson_is_arr(arr))
		goto out;

	merkles = yyjson_arr_size(arr);
	/* merklehash is a fixed size array so reject rather than overflow it */
	if (unlikely(merkles > 16)) {
		LOGWARNING("Proxy %d:%d received notify with %d merkles, exceeding max of 16",
			   proxi->id, proxi->subid, merkles);
		goto out;
	}
	jid = yyjson_arr_get(val, 0);
	if (jid) {
		job_id = yyjson_mut_doc_new(&ckyyalc);
		yyjson_mut_doc_set_root(job_id, yyjson_val_mut_copy(job_id, jid));
	}
	prev_hash = yyjson_get_str(yyjson_arr_get(val, 1));
	string = yyjson_get_str(yyjson_arr_get(val, 2));
	if (string)
		coinbase1 = strdup(string);
	string = yyjson_get_str(yyjson_arr_get(val, 3));
	if (string)
		coinbase2 = strdup(string);
	bbversion = yyjson_get_str(yyjson_arr_get(val, 5));
	nbit = yyjson_get_str(yyjson_arr_get(val, 6));
	ntime = yyjson_get_str(yyjson_arr_get(val, 7));
	clean = yyjson_is_true(yyjson_arr_get(val, 8));
	if (!job_id || !prev_hash || !coinbase1 || !coinbase2 || !bbversion || !nbit || !ntime)
		goto out_free;
	/* These are all fixed length hex fields so reject anything else to
	 * avoid overreading them or overflowing the fixed size arrays they
	 * are copied to. */
	if (unlikely(strlen(prev_hash) != 64 || strlen(bbversion) != 8 || strlen(nbit) != 8 ||
		     strlen(ntime) != 8)) {
		LOGWARNING("Proxy %d:%d received notify with invalid header field lengths",
			   proxi->id, proxi->subid);
		goto out_free;
	}
	/* Coinbase values are hex strings and must be of even length */
	if (unlikely(!strlen(coinbase1) || strlen(coinbase1) % 2 || strlen(coinbase2) % 2)) {
		LOGWARNING("Proxy %d:%d received notify with invalid coinbase lengths",
			   proxi->id, proxi->subid);
		goto out_free;
	}
	for (i = 0; i < merkles; i++) {
		const char *merkle = yyjson_get_str(yyjson_arr_get(arr, i));

		/* Each merkle hash is a fixed 64 hex char (32 byte) value */
		if (unlikely(!merkle || strlen(merkle) != 64)) {
			LOGWARNING("Proxy %d:%d received notify with invalid merkle hash",
				   proxi->id, proxi->subid);
			goto out_free;
		}
	}

	LOGDEBUG("Received new notify from proxy %d:%d", proxi->id, proxi->subid);
	ni = ckzalloc(sizeof(notify_instance_t));
	ni->jobid = job_id;
	jobidbuf = yyjson_get_str(jid);
	LOGDEBUG("JobID %s", jobidbuf);
	ni->coinbase1 = coinbase1;
	LOGDEBUG("Coinbase1 %s", coinbase1);
	ni->coinb1len = strlen(coinbase1) / 2;
	ni->coinbase2 = coinbase2;
	LOGDEBUG("Coinbase2 %s", coinbase2);
	memcpy(ni->prevhash, prev_hash, 65);
	LOGDEBUG("Prevhash %s", prev_hash);
	memcpy(ni->bbversion, bbversion, 9);
	LOGDEBUG("BBVersion %s", bbversion);
	memcpy(ni->nbit, nbit, 9);
	LOGDEBUG("Nbit %s", nbit);
	memcpy(ni->ntime, ntime, 9);
	LOGDEBUG("Ntime %s", ntime);
	ni->clean = clean;
	LOGDEBUG("Clean %s", clean ? "true" : "false");
	LOGDEBUG("Merkles %d", merkles);
	for (i = 0; i < merkles; i++) {
		const char *merkle = yyjson_get_str(yyjson_arr_get(arr, i));

		LOGDEBUG("Merkle %d %s", i, merkle);
		memcpy(&ni->merklehash[i][0], merkle, 65);
	}
	ni->merkles = merkles;
	ret = true;
	ni->notify_time = time(NULL);

	/* Add the notify instance to the parent proxy list, not the subproxy */
	mutex_lock(&gdata->notify_lock);
	ni->id64 = gdata->proxy_notify_id++;
	HASH_ADD_I64(gdata->notify_instances, id64, ni);
	mutex_unlock(&gdata->notify_lock);

	send_notify(proxi, ni);
	goto out;
out_free:
	if (job_id)
		yyjson_mut_doc_free(job_id);
	if (coinbase1)
		free(coinbase1);
	if (coinbase2)
		free(coinbase2);
out:
	return ret;
}

static bool parse_diff(proxy_instance_t *proxi, yyjson_val *val)
{
	double diff = yyjson_get_num(yyjson_arr_get(val, 0));

	/* Ignore non finite or negative values that would wedge all the diff
	 * calculations derived from this */
	if (!isfinite(diff) || diff <= 0 || diff == proxi->diff)
		return true;
	proxi->diff = diff;
	return true;
}

static bool send_version(proxy_instance_t *proxi, yyjson_val *val)
{
	yyjson_mut_doc *doc = yyjson_mut_doc_new(&ckyyalc);
	yyjson_mut_val *root;
	bool ret;

	root = yyjson_mut_pack_val(doc, "{sosssn}", "id",
				   yyjson_val_mut_copy(doc, yyjson_obj_get(val, "id")),
				   "result", PACKAGE"/"VERSION, "error");
	yyjson_mut_doc_set_root(doc, root);
	ret = send_yyjson_msg(&proxi->cs, doc);
	yyjson_mut_doc_free(doc);
	return ret;
}

static bool show_message(yyjson_val *val)
{
	const char *msg;

	if (!yyjson_is_arr(val))
		return false;
	msg = yyjson_get_str(yyjson_arr_get(val, 0));
	if (!msg)
		return false;
	LOGNOTICE("Pool message: %s", msg);
	return true;
}

static bool send_pong(proxy_instance_t *proxi, yyjson_val *val)
{
	yyjson_mut_doc *doc = yyjson_mut_doc_new(&ckyyalc);
	yyjson_mut_val *root;
	bool ret;

	root = yyjson_mut_pack_val(doc, "{sosssn}", "id",
				   yyjson_val_mut_copy(doc, yyjson_obj_get(val, "id")),
				   "result", "pong", "error");
	yyjson_mut_doc_set_root(doc, root);
	ret = send_yyjson_msg(&proxi->cs, doc);
	yyjson_mut_doc_free(doc);
	return ret;
}

static void prepare_proxy(proxy_instance_t *proxi);

/* Creates a duplicate instance or proxi to be used as a subproxy, ignoring
 * fields we don't use in the subproxy. */
static proxy_instance_t *create_subproxy(gdata_t *gdata, proxy_instance_t *proxi,
					 const char *url, const char *baseurl)
{
	proxy_instance_t *subproxy;

	mutex_lock(&gdata->lock);
	if (gdata->dead_proxies) {
		/* Recycle an old proxy instance if one exists */
		subproxy = gdata->dead_proxies;
		DL_DELETE(gdata->dead_proxies, subproxy);
	} else {
		gdata->subproxies_generated++;
		subproxy = ckzalloc(sizeof(proxy_instance_t));
	}
	mutex_unlock(&gdata->lock);

	mutex_lock(&proxi->proxy_lock);
	subproxy->subid = ++proxi->subproxy_count;
	mutex_unlock(&proxi->proxy_lock);

	subproxy->id = proxi->id;
	subproxy->userid = proxi->userid;
	subproxy->global = proxi->global;
	subproxy->url = strdup(url);
	subproxy->baseurl = strdup(baseurl);
	subproxy->auth = strdup(proxi->auth);
	subproxy->pass = strdup(proxi->pass);
	subproxy->parent = proxi;
	subproxy->epfd = proxi->epfd;
	cksem_init(&subproxy->cs.sem);
	cksem_post(&subproxy->cs.sem);
	return subproxy;
}

static void add_subproxy(proxy_instance_t *proxi, proxy_instance_t *subproxy)
{
	mutex_lock(&proxi->proxy_lock);
	HASH_ADD(sh, proxi->subproxies, subid, sizeof(int), subproxy);
	mutex_unlock(&proxi->proxy_lock);
}

static proxy_instance_t *__subproxy_by_id(proxy_instance_t *proxy, const int subid)
{
	proxy_instance_t *subproxy;

	HASH_FIND(sh, proxy->subproxies, &subid, sizeof(int), subproxy);
	return subproxy;
}

/* Add to the dead list to be recycled if possible */
static void store_proxy(gdata_t *gdata, proxy_instance_t *proxy)
{
	LOGINFO("Recycling data from proxy %d:%d", proxy->id, proxy->subid);

	mutex_lock(&gdata->lock);
	dealloc(proxy->enonce1);
	dealloc(proxy->url);
	dealloc(proxy->baseurl);
	dealloc(proxy->auth);
	dealloc(proxy->pass);
	dealloc(proxy->enonce1bin);
	memset(proxy, 0, sizeof(proxy_instance_t));
	DL_APPEND(gdata->dead_proxies, proxy);
	mutex_unlock(&gdata->lock);
}

/* The difference between a dead proxy and a deleted one is the parent proxy entry
 * is not removed from the stratifier as it assumes it is down whereas a deleted
 * proxy has had its entry removed from the generator. */
static void send_stratifier_deadproxy(const int id, const int subid)
{
	char buf[256];

	if (ckpool.passthrough)
		return;
	sprintf(buf, "deadproxy=%d:%d", id, subid);
	send_proc(ckpool.stratifier, buf);
}

static void send_stratifier_delproxy(const int id, const int subid)
{
	char buf[256];

	if (ckpool.passthrough)
		return;
	sprintf(buf, "delproxy=%d:%d", id, subid);
	send_proc(ckpool.stratifier, buf);
}

/* Close the subproxy socket if it's open and remove it from the epoll list */
static void close_proxy_socket(proxy_instance_t *proxy, proxy_instance_t *subproxy)
{
	if (subproxy->cs.fd > 0) {
		epoll_ctl(proxy->epfd, EPOLL_CTL_DEL, subproxy->cs.fd, NULL);
		Close(subproxy->cs.fd);
	}
}

/* Remove the subproxy from the proxi list and put it on the dead list.
 * Further use of the subproxy pointer may point to a new proxy but will not
 * dereference. This will only disable subproxies so parent proxies need to
 * have their disabled bool set manually. */
static void disable_subproxy(gdata_t *gdata, proxy_instance_t *proxi, proxy_instance_t *subproxy)
{
	subproxy->alive = false;
	send_stratifier_deadproxy(subproxy->id, subproxy->subid);
	close_proxy_socket(proxi, subproxy);
	if (parent_proxy(subproxy))
		return;

	subproxy->disabled = true;

	mutex_lock(&proxi->proxy_lock);
	/* Make sure subproxy is still in the list */
	subproxy = __subproxy_by_id(proxi, subproxy->subid);
	if (likely(subproxy))
		HASH_DELETE(sh, proxi->subproxies, subproxy);
	mutex_unlock(&proxi->proxy_lock);

	if (subproxy) {
		send_stratifier_deadproxy(subproxy->id, subproxy->subid);
		store_proxy(gdata, subproxy);
	}
}

static bool parse_reconnect(proxy_instance_t *proxy, yyjson_val *val)
{
	bool sameurl = false, ret = false;
	gdata_t *gdata = ckpool.gdata;
	proxy_instance_t *parent;
	const char *new_url;
	int new_port;
	char *url;

	new_url = yyjson_get_str(yyjson_arr_get(val, 0));
	new_port = yyjson_get_sint(yyjson_arr_get(val, 1));
	/* See if we have an invalid entry listing port as a string instead of
	 * integer and handle that. */
	if (!new_port) {
		const char *newport_string = yyjson_get_str(yyjson_arr_get(val, 1));

		if (newport_string)
			sscanf(newport_string, "%d", &new_port);
	}
	if (new_url && strlen(new_url) && new_port) {
		char *dot_pool, *dot_reconnect;
		int len;

		dot_pool = strchr(proxy->url, '.');
		if (!dot_pool) {
			LOGWARNING("Denied stratum reconnect request from server without domain %s",
				   proxy->url);
			goto out;
		}
		dot_reconnect = strchr(new_url, '.');
		if (!dot_reconnect) {
			LOGWARNING("Denied stratum reconnect request to url without domain %s",
				   new_url);
			goto out;
		}
		len = strlen(dot_reconnect);
		if (strncmp(dot_pool, dot_reconnect, len)) {
			LOGWARNING("Denied stratum reconnect request from %s to non-matching domain %s",
				   proxy->url, new_url);
			goto out;
		}
		ASPRINTF(&url, "%s:%d", new_url, new_port);
	} else {
		url = strdup(proxy->url);
		sameurl = true;
	}
	LOGINFO("Processing reconnect request to %s", url);

	ret = true;
	parent = proxy->parent;
	disable_subproxy(gdata, parent, proxy);
	if (parent != proxy) {
		/* If this is a subproxy we only need to create a new one if
		 * the url has changed. Otherwise automated recruiting will
		 * take care of creating one if needed. */
		if (!sameurl)
			create_subproxy(gdata, parent, url, parent->baseurl);
		goto out;
	}

	proxy->reconnect = true;
	LOGWARNING("Proxy %d:%s reconnect issue to %s, dropping existing connection",
		   proxy->id, proxy->url, url);
	if (!sameurl) {
		char *oldurl = proxy->url;

		proxy->url = url;
		free(oldurl);
	} else
		free(url);
out:
	return ret;
}

static void send_diff(proxy_instance_t *proxi)
{
	proxy_instance_t *proxy = proxi->parent;
	yyjson_mut_doc *doc;
	char *msg, *buf;

	/* Not set yet */
	if (!proxi->diff)
		return;

	doc = yyjson_mut_pack("{sisisf}",
			      "proxy", proxy->id,
			      "subproxy", proxi->subid,
			      "diff", proxi->diff);
	msg = yyjson_mut_write(doc, 0, NULL);
	yyjson_mut_doc_free(doc);
	ASPRINTF(&buf, "diff=%s", msg);
	free(msg);
	send_proc(ckpool.stratifier, buf);
	free(buf);
}

static void send_notify(proxy_instance_t *proxi, notify_instance_t *ni)
{
	proxy_instance_t *proxy = proxi->parent;
	yyjson_mut_val *root, *merkle_arr;
	yyjson_mut_doc *doc;
	char *msg, *buf;
	int i;

	doc = yyjson_mut_doc_new(&ckyyalc);
	merkle_arr = yyjson_mut_arr(doc);

	for (i = 0; i < ni->merkles; i++)
		yyjson_mut_arr_add_strcpy(doc, merkle_arr, &ni->merklehash[i][0]);
	/* Use our own jobid instead of the server's one for easy lookup */
	root = yyjson_mut_pack_val(doc, "{sisisIsssisssssosssssssb}",
			     "proxy", proxy->id, "subproxy", proxi->subid,
			     "jobid", ni->id64, "prevhash", ni->prevhash, "coinb1len", ni->coinb1len,
			     "coinbase1", ni->coinbase1, "coinbase2", ni->coinbase2,
			     "merklehash", merkle_arr, "bbversion", ni->bbversion,
			     "nbit", ni->nbit, "ntime", ni->ntime,
			     "clean", ni->clean);
	yyjson_mut_doc_set_root(doc, root);

	msg = yyjson_mut_write(doc, 0, NULL);
	yyjson_mut_doc_free(doc);
	ASPRINTF(&buf, "notify=%s", msg);
	free(msg);
	send_proc(ckpool.stratifier, buf);
	free(buf);

	/* Send diff now as stratifier will not accept diff till it has a
	 * valid workbase */
	send_diff(proxi);
}

static bool parse_method(proxy_instance_t *proxi, const char *msg)
{
	yyjson_val *val, *method, *err_val, *params;
	yyjson_doc *doc = NULL;
	bool ret = false;
	const char *buf;

	if (!msg)
		goto out;
	doc = yyjson_read(msg, strlen(msg), 0);
	if (!doc) {
		if (proxi->global) {
			LOGWARNING("JSON decode of proxy %d:%s msg %s failed",
				   proxi->id, proxi->url, msg);
		} else {
			LOGNOTICE("JSON decode of proxy %d:%s msg %s failed",
				  proxi->id, proxi->url, msg);
		}
		goto out;
	}
	val = yyjson_doc_get_root(doc);

	method = yyjson_obj_get(val, "method");
	if (!method) {
		/* Likely a share, look for harmless unhandled methods in
		 * pool response */
		if (strstr(msg, "mining.suggest")) {
			LOGINFO("Unhandled suggest_diff from proxy %d:%s", proxi->id, proxi->url);
			ret = true;
		} else
			LOGDEBUG("Failed to find method in json for parse_method");
		goto out;
	}
	err_val = yyjson_obj_get(val, "error");
	params = yyjson_obj_get(val, "params");

	if (err_val && !yyjson_is_null(err_val)) {
		char *ss;

		if (err_val)
			ss = yyjson_val_write(err_val, 0, NULL);
		else
			ss = strdup("(unknown reason)");

		LOGINFO("JSON-RPC method decode failed: %s", ss);
		free(ss);
		goto out;
	}

	if (!yyjson_is_str(method)) {
		LOGINFO("Method is not string in parse_method");
		goto out;
	}
	buf = yyjson_get_str(method);
	if (!buf || strlen(buf) < 1) {
		LOGINFO("Invalid string for method in parse_method");
		goto out;
	}

	LOGDEBUG("Proxy %d:%d received method %s", proxi->id, proxi->subid, buf);
	if (cmdmatch(buf, "mining.notify")) {
		ret = parse_notify(proxi, params);
		goto out;
	}

	if (cmdmatch(buf, "mining.set_difficulty")) {
		ret = parse_diff(proxi, params);
		if (likely(ret))
			send_diff(proxi);
		goto out;
	}

	if (cmdmatch(buf, "client.reconnect")) {
		ret = parse_reconnect(proxi, params);
		goto out;
	}

	if (cmdmatch(buf, "client.get_version")) {
		ret =  send_version(proxi, val);
		goto out;
	}

	if (cmdmatch(buf, "client.show_message")) {
		ret = show_message(params);
		goto out;
	}

	if (cmdmatch(buf, "mining.ping")) {
		ret = send_pong(proxi, val);
		goto out;
	}
out:
	if (doc)
		yyjson_doc_free(doc);
	return ret;
}

/* cs semaphore must be held */
static bool auth_stratum(connsock_t *cs, proxy_instance_t *proxi)
{
	yyjson_val *res_val, *err_val;
	yyjson_doc *val = NULL;
	yyjson_mut_doc *req;
	char *buf = NULL;
	bool ret;

	req = yyjson_mut_pack("{s:i,s:s,s:[s,s]}",
			      "id", 42,
			      "method", "mining.authorize",
			      "params", proxi->auth, proxi->pass);
	ret = send_yyjson_msg(cs, req);
	yyjson_mut_doc_free(req);
	if (!ret) {
		LOGNOTICE("Proxy %d:%d %s failed to send message in auth_stratum",
			  proxi->id, proxi->subid, proxi->url);
		if (cs->fd > 0) {
			epoll_ctl(proxi->epfd, EPOLL_CTL_DEL, cs->fd, NULL);
			Close(cs->fd);
		}
		goto out;
	}

	/* Read and parse any extra methods sent. Anything left in the buffer
	 * should be the response to our auth request. */
	do {
		free(buf);
		buf = next_proxy_line(cs, proxi);
		if (!buf) {
			LOGNOTICE("Proxy %d:%d %s failed to receive line in auth_stratum",
				  proxi->id, proxi->subid, proxi->url);
			ret = false;
			goto out;
		}
		ret = parse_method(proxi, buf);
	} while (ret);

	val = yyjson_msg_result(buf, &res_val, &err_val);
	if (!val) {
		if (proxi->global) {
			LOGWARNING("Proxy %d:%d %s failed to get a json result in auth_stratum, got: %s",
				   proxi->id, proxi->subid, proxi->url, buf);
		} else {
			LOGNOTICE("Proxy %d:%d %s failed to get a json result in auth_stratum, got: %s",
				  proxi->id, proxi->subid, proxi->url, buf);
		}
		goto out;
	}

	if (err_val && !yyjson_is_null(err_val)) {
		LOGWARNING("Proxy %d:%d %s failed to authorise in auth_stratum due to err_val, got: %s",
			   proxi->id, proxi->subid, proxi->url, buf);
		goto out;
	}
	if (res_val) {
		ret = yyjson_is_true(res_val);
		if (!ret) {
			if (proxi->global) {
				LOGWARNING("Proxy %d:%d %s failed to authorise in auth_stratum, got: %s",
					   proxi->id, proxi->subid, proxi->url, buf);
			} else {
				LOGNOTICE("Proxy %d:%d %s failed to authorise in auth_stratum, got: %s",
					  proxi->id, proxi->subid, proxi->url, buf);
			}
			goto out;
		}
	} else {
		/* No result and no error but successful val means auth success */
		ret = true;
	}
	LOGINFO("Proxy %d:%d %s auth success in auth_stratum", proxi->id, proxi->subid, proxi->url);
out:
	if (val)
		yyjson_doc_free(val);
	if (ret) {
		/* Now parse any cached responses so there are none in the
		 * queue and they can be managed one at a time from now on. */
		while(42) {
			dealloc(buf);
			buf = cached_proxy_line(proxi);
			if (!buf)
				break;
			parse_method(proxi, buf);
		};
	}
	return ret;
}

static proxy_instance_t *proxy_by_id(gdata_t *gdata, const int id)
{
	proxy_instance_t *proxi;

	mutex_lock(&gdata->lock);
	HASH_FIND_INT(gdata->proxies, &id, proxi);
	mutex_unlock(&gdata->lock);

	return proxi;
}

static void send_subscribe(proxy_instance_t *proxi)
{
	yyjson_mut_doc *doc;
	char *msg, *buf;

	doc = yyjson_mut_pack("{ss,ss,ss,ss,si,si,ss,si,sb,si}",
			      "baseurl", proxi->baseurl,
			      "url", proxi->url, "auth", proxi->auth, "pass", proxi->pass,
			      "proxy", proxi->id, "subproxy", proxi->subid,
			      "enonce1", proxi->enonce1, "nonce2len", proxi->nonce2len,
			      "global", proxi->global, "userid", proxi->userid);
	msg = yyjson_mut_write(doc, 0, NULL);
	yyjson_mut_doc_free(doc);
	ASPRINTF(&buf, "subscribe=%s", msg);
	free(msg);
	send_proc(ckpool.stratifier, buf);
	free(buf);
}

static proxy_instance_t *subproxy_by_id(proxy_instance_t *proxy, const int subid)
{
	proxy_instance_t *subproxy;

	mutex_lock(&proxy->proxy_lock);
	subproxy = __subproxy_by_id(proxy, subid);
	mutex_unlock(&proxy->proxy_lock);

	return subproxy;
}

static void drop_proxy(gdata_t *gdata, const char *buf)
{
	proxy_instance_t *proxy, *subproxy;
	int id = -1, subid = -1;

	sscanf(buf, "dropproxy=%d:%d", &id, &subid);
	if (unlikely(!subid)) {
		LOGWARNING("Generator asked to drop parent proxy %d", id);
		return;
	}
	proxy = proxy_by_id(gdata, id);
	if (unlikely(!proxy)) {
		LOGINFO("Generator asked to drop subproxy from non-existent parent %d", id);
		return;
	}
	subproxy = subproxy_by_id(proxy, subid);
	if (!subproxy) {
		LOGINFO("Generator asked to drop non-existent subproxy %d:%d", id, subid);
		return;
	}
	LOGNOTICE("Generator asked to drop proxy %d:%d", id, subid);
	disable_subproxy(gdata, proxy, subproxy);
}

static void stratifier_reconnect_client(const int64_t id)
{
	char buf[256];

	sprintf(buf, "reconnclient=%"PRId64, id);
	send_proc(ckpool.stratifier, buf);
}

/* Add a share to the gdata share hashlist. Returns the share id */
static int add_share(gdata_t *gdata, const int64_t client_id, const double diff)
{
	share_msg_t *share = ckzalloc(sizeof(share_msg_t)), *tmpshare;
	time_t now;
	int ret;

	share->submit_time = now = time(NULL);
	share->client_id = client_id;
	share->diff = diff;

	/* Add new share entry to the share hashtable. Age old shares */
	mutex_lock(&gdata->share_lock);
	ret = share->id64 = gdata->share_id++;
	HASH_ADD_I64(gdata->shares, id64, share);
	HASH_ITER(hh, gdata->shares, share, tmpshare) {
		if (share->submit_time < now - 120) {
			HASH_DEL(gdata->shares, share);
			free(share);
		}
	}
	mutex_unlock(&gdata->share_lock);

	return ret;
}

static void submit_share(gdata_t *gdata, yyjson_mut_doc *doc)
{
	yyjson_mut_val *val = yyjson_mut_doc_get_root(doc);
	proxy_instance_t *proxy, *proxi;
	int id, subid, share_id;
	bool success = false;
	stratum_msg_t *msg;
	int64_t client_id;

	/* Get the client id so we can tell the stratifier to drop it if the
	 * proxy it's bound to is not functional */
	if (unlikely(!yyjson_mut_obj_get_int64(&client_id, val, "client_id"))) {
		LOGWARNING("Got no client_id in share");
		goto out;
	}
	if (unlikely(!yyjson_mut_obj_get_int(&id, val, "proxy"))) {
		LOGWARNING("Got no proxy in share");
		goto out;
	}
	if (unlikely(!yyjson_mut_obj_get_int(&subid, val, "subproxy"))) {
		LOGWARNING("Got no subproxy in share");
		goto out;
	}
	proxy = proxy_by_id(gdata, id);
	if (unlikely(!proxy)) {
		LOGINFO("Client %"PRId64" sending shares to non existent proxy %d, dropping",
			client_id, id);
		stratifier_reconnect_client(client_id);
		goto out;
	}
	proxi = subproxy_by_id(proxy, subid);
	if (unlikely(!proxi)) {
		LOGINFO("Client %"PRId64" sending shares to non existent subproxy %d:%d, dropping",
			client_id, id, subid);
		stratifier_reconnect_client(client_id);
		goto out;
	}
	if (!proxi->alive) {
		LOGINFO("Client %"PRId64" sending shares to dead subproxy %d:%d, dropping",
			client_id, id, subid);
		stratifier_reconnect_client(client_id);
		goto out;
	}

	success = true;
	msg = ckzalloc(sizeof(stratum_msg_t));
	msg->doc = doc;
	share_id = add_share(gdata, client_id, proxi->diff);
	yyjson_mut_obj_add_int(doc, val, "id", share_id);

	/* Add the new message to the psend list */
	mutex_lock(&gdata->psend_lock);
	gdata->psends_generated++;
	DL_APPEND(gdata->psends, msg);
	pthread_cond_signal(&gdata->psend_cond);
	mutex_unlock(&gdata->psend_lock);

out:
	if (!success)
		yyjson_mut_doc_free(doc);
}

static void clear_notify(notify_instance_t *ni)
{
	if (ni->jobid)
		yyjson_mut_doc_free(ni->jobid);
	free(ni->coinbase1);
	free(ni->coinbase2);
	free(ni);
}

/* Entered with proxy_lock held */
static void __decay_proxy(proxy_instance_t *proxy, proxy_instance_t * parent, const double diff)
{
	double tdiff;
	tv_t now_t;

	tv_time(&now_t);
	tdiff = sane_tdiff(&now_t, &proxy->last_decay);
	decay_time(&proxy->dsps1, diff, tdiff, MIN1);
	decay_time(&proxy->dsps5, diff, tdiff, MIN5);
	decay_time(&proxy->dsps60, diff, tdiff, HOUR);
	decay_time(&proxy->dsps1440, diff, tdiff, DAY);
	copy_tv(&proxy->last_decay, &now_t);

	tdiff = sane_tdiff(&now_t, &parent->total_last_decay);
	decay_time(&parent->tdsps1, diff, tdiff, MIN1);
	decay_time(&parent->tdsps5, diff, tdiff, MIN5);
	decay_time(&parent->tdsps60, diff, tdiff, HOUR);
	decay_time(&parent->tdsps1440, diff, tdiff, DAY);
	copy_tv(&parent->total_last_decay, &now_t);
}

static void account_shares(proxy_instance_t *proxy, const double diff, const bool result)
{
	proxy_instance_t *parent = proxy->parent;

	mutex_lock(&parent->proxy_lock);
	if (result) {
		proxy->diff_accepted += diff;
		parent->total_accepted += diff;
		__decay_proxy(proxy, parent, diff);
	} else {
		proxy->diff_rejected += diff;
		parent->total_rejected += diff;
		__decay_proxy(proxy, parent, 0);
	}
	mutex_unlock(&parent->proxy_lock);
}

/* Returns zero if it is not recognised as a share, 1 if it is a valid share
 * and -1 if it is recognised as a share but invalid. */
static int parse_share(gdata_t *gdata, proxy_instance_t *proxi, const char *buf)
{
	yyjson_val *val, *idval;
	yyjson_doc *doc = NULL;
	bool result = false;
	share_msg_t *share;
	int ret = 0;
	int64_t id;

	doc = yyjson_read(buf, strlen(buf), 0);
	if (unlikely(!doc)) {
		LOGINFO("Failed to parse upstream json msg: %s", buf);
		goto out;
	}
	val = yyjson_doc_get_root(doc);
	idval = yyjson_obj_get(val, "id");
	if (unlikely(!idval)) {
		LOGINFO("Failed to find id in upstream json msg: %s", buf);
		goto out;
	}
	id = yyjson_get_sint(idval);
	{
		yyjson_val *res_val = yyjson_obj_get(val, "result");

		if (!yyjson_is_bool(res_val)) {
			yyjson_val *err_val = yyjson_obj_get(val, "error");

			if (unlikely(!(yyjson_is_null(res_val) && err_val && !yyjson_is_null(err_val)))) {
				LOGINFO("Failed to find result in upstream json msg: %s", buf);
				goto out;
			}
			result = false;
		} else
			result = yyjson_get_bool(res_val);
	}

	mutex_lock(&gdata->share_lock);
	HASH_FIND_I64(gdata->shares, &id, share);
	if (share) {
		HASH_DEL(gdata->shares, share);
		free(share);
	}
	mutex_unlock(&gdata->share_lock);

	if (!share) {
		LOGINFO("Proxy %d:%d failed to find matching share to result: %s",
			proxi->id, proxi->subid, buf);
		/* We don't know what diff these shares are so assume the
		 * current proxy diff. */
		account_shares(proxi, proxi->diff, result);
		ret = -1;
		goto out;
	}
	ret = 1;
	account_shares(proxi, share->diff, result);
	LOGINFO("Proxy %d:%d share result %s from client %"PRId64, proxi->id, proxi->subid,
		buf, share->client_id);
	free(share);
out:
	if (doc)
		yyjson_doc_free(doc);
	return ret;
}

struct cs_msg {
	cs_msg_t *next;
	cs_msg_t *prev;
	proxy_instance_t *proxy;
	char *buf;
	int len;
	int ofs;
};

/* Sends all messages in the queue ready to be dispatched, leaving those that
 * would block to be handled next pass */
static void send_json_msgq(gdata_t *gdata, cs_msg_t **csmsgq)
{
	cs_msg_t *csmsg, *tmp;
	int ret;

	DL_FOREACH_SAFE(*csmsgq, csmsg, tmp) {
		proxy_instance_t *proxy = csmsg->proxy;

		/* Only try to send one message at a time to each proxy
		 * to avoid sending parts of different messages */
		if (proxy->sending  && proxy->sending != csmsg)
			continue;
		while (csmsg->len > 0) {
			int fd;

			if (unlikely(!proxy->alive)) {
				LOGDEBUG("Dropping send message to dead proxy %d:%d in send_json_msgq",
					 proxy->id, proxy->subid);
				csmsg->len = 0;
				break;
			}
			proxy->sending = csmsg;
			fd = proxy->cs.fd;
			ret = send(fd, csmsg->buf + csmsg->ofs, csmsg->len, MSG_DONTWAIT);
			if (ret < 1) {
				if (!ret)
					break;
				ret = 0;
				if (errno == EAGAIN || errno == EWOULDBLOCK)
					break;
				csmsg->len = 0;
				LOGNOTICE("Proxy %d:%d %s failed to send msg in send_json_msgq, dropping",
					  proxy->id, proxy->subid, proxy->url);
				disable_subproxy(gdata, proxy->parent, proxy);
			}
			csmsg->ofs += ret;
			csmsg->len -= ret;
		}
		if (csmsg->len < 1) {
			proxy->sending = NULL;
			DL_DELETE(*csmsgq, csmsg);
			free(csmsg->buf);
			free(csmsg);
		}
	}
}

static void add_yyjson_msgq(cs_msg_t **csmsgq, proxy_instance_t *proxy, yyjson_mut_doc *doc)
{
	cs_msg_t *csmsg = ckzalloc(sizeof(cs_msg_t));
	size_t len = 0;

	csmsg->buf = yyjson_mut_write(doc, YYJSON_WRITE_NEWLINE_AT_END, &len);
	yyjson_mut_doc_free(doc);
	if (unlikely(!csmsg->buf)) {
		LOGWARNING("Failed to create json dump in add_yyjson_msgq");
		free(csmsg);
		return;
	}
	csmsg->len = len;
	csmsg->proxy = proxy;
	DL_APPEND(*csmsgq, csmsg);
}

/* For processing and sending shares. proxy refers to parent proxy here */
static void *proxy_send(void __maybe_unused *arg)
{
	gdata_t *gdata = ckpool.gdata;
	stratum_msg_t *msg = NULL;
	cs_msg_t *csmsgq = NULL;

	rename_proc("proxysend");

	pthread_detach(pthread_self());

	while (42) {
		int proxyid = 0, subid = 0, share_id = 0;
		proxy_instance_t *proxy, *subproxy;
		yyjson_mut_val *root, *sroot, *jobid;
		int64_t client_id = 0, id;
		notify_instance_t *ni;
		yyjson_mut_doc *doc;

		if (unlikely(msg)) {
			yyjson_mut_doc_free(msg->doc);
			free(msg);
		}

		mutex_lock(&gdata->psend_lock);
		if (!gdata->psends) {
			/* Poll every 10ms */
			const ts_t polltime = {0, 10000000};
			ts_t timeout_ts;

			ts_realtime(&timeout_ts);
			timeraddspec(&timeout_ts, &polltime);
			cond_timedwait(&gdata->psend_cond, &gdata->psend_lock, &timeout_ts);
		}
		msg = gdata->psends;
		if (likely(msg))
			DL_DELETE(gdata->psends, msg);
		mutex_unlock(&gdata->psend_lock);

		if (!msg) {
			send_json_msgq(gdata, &csmsgq);
			continue;
		}

		sroot = yyjson_mut_doc_get_root(msg->doc);
		if (unlikely(!yyjson_mut_obj_get_int(&subid, sroot, "subproxy"))) {
			LOGWARNING("Failed to find subproxy in proxy_send msg");
			continue;
		}
		if (unlikely(!yyjson_mut_obj_get_int64(&id, sroot, "jobid"))) {
			LOGWARNING("Failed to find jobid in proxy_send msg");
			continue;
		}
		if (unlikely(!yyjson_mut_obj_get_int(&proxyid, sroot, "proxy"))) {
			LOGWARNING("Failed to find proxy in proxy_send msg");
			continue;
		}
		if (unlikely(!yyjson_mut_obj_get_int64(&client_id, sroot, "client_id"))) {
			LOGWARNING("Failed to find client_id in proxy_send msg");
			continue;
		}
		yyjson_mut_obj_get_int(&share_id, sroot, "id");
		proxy = proxy_by_id(gdata, proxyid);
		if (unlikely(!proxy)) {
			LOGWARNING("Proxysend for got message for non-existent proxy %d",
				   proxyid);
			continue;
		}
		subproxy = subproxy_by_id(proxy, subid);
		if (unlikely(!subproxy)) {
			LOGWARNING("Proxysend for got message for non-existent subproxy %d:%d",
				   proxyid, subid);
			continue;
		}

		doc = yyjson_mut_doc_new(&ckyyalc);
		jobid = NULL;
		mutex_lock(&gdata->notify_lock);
		HASH_FIND_INT(gdata->notify_instances, &id, ni);
		if (ni)
			jobid = yyjson_mut_val_mut_copy(doc, yyjson_mut_doc_get_root(ni->jobid));
		mutex_unlock(&gdata->notify_lock);

		if (unlikely(!jobid)) {
			stratifier_reconnect_client(client_id);
			LOGNOTICE("Proxy %d:%s failed to find matching jobid in proxysend",
				  subproxy->id, subproxy->url);
			yyjson_mut_doc_free(doc);
			continue;
		}

		root = yyjson_mut_pack_val(doc, "{s[sosss]siss}", "params", subproxy->auth,
				jobid,
				yyjson_mut_get_str(yyjson_mut_obj_get(sroot, "nonce2")),
				yyjson_mut_get_str(yyjson_mut_obj_get(sroot, "ntime")),
				yyjson_mut_get_str(yyjson_mut_obj_get(sroot, "nonce")),
				"id", share_id,
				"method", "mining.submit");
		yyjson_mut_doc_set_root(doc, root);
		add_yyjson_msgq(&csmsgq, subproxy, doc);
		send_json_msgq(gdata, &csmsgq);
	}
	return NULL;
}

static void passthrough_send(pass_msg_t *pm)
{
	proxy_instance_t *proxy = pm->proxy;
	connsock_t *cs = pm->cs;
	int len, sent;

	if (unlikely(!proxy->alive || cs->fd < 0)) {
		LOGDEBUG("Dropping send to dead proxy of upstream json msg: %s", pm->msg);
		goto out;
	}
	LOGDEBUG("Sending upstream json msg: %s", pm->msg);
	len = strlen(pm->msg);
	sent = write_socket(cs->fd, pm->msg, len);
	if (unlikely(sent != len)) {
		LOGWARNING("Failed to passthrough %d bytes of message %s, attempting reconnect",
			   len, pm->msg);
		Close(cs->fd);
		proxy->alive = false;
		reconnect_generator();
	}
out:
	free(pm->msg);
	free(pm);
}

static void passthrough_add_send(proxy_instance_t *proxy, char *msg)
{
	pass_msg_t *pm = ckzalloc(sizeof(pass_msg_t));

	pm->proxy = proxy;
	pm->cs = &proxy->cs;
	pm->msg = msg;
	ckmsgq_add(proxy->passsends, pm);
}

void generator_add_send(yyjson_mut_doc *doc)
{
	gdata_t *gdata = ckpool.gdata;
	char *buf;

	if (!ckpool.passthrough) {
		submit_share(gdata, doc);
		return;
	}
	if (unlikely(!gdata->current_proxy)) {
		LOGWARNING("No current proxy to send passthrough data to");
		goto out;
	}
	buf = yyjson_mut_write(doc, YYJSON_WRITE_NEWLINE_AT_END, NULL);
	if (unlikely(!buf)) {
		LOGWARNING("Unable to decode json in generator_add_send");
		goto out;
	}
	passthrough_add_send(gdata->current_proxy, buf);
out:
	yyjson_mut_doc_free(doc);
}

static void suggest_diff(connsock_t *cs, proxy_instance_t *proxy)
{
	yyjson_mut_doc *req;
	bool ret;

	req = yyjson_mut_pack("{s:i,s:s, s:[I]}",
			      "id", 41,
			      "method", "mining.suggest",
			      "params", ckpool.mindiff);
	ret = send_yyjson_msg(cs, req);
	yyjson_mut_doc_free(req);
	if (!ret) {
		LOGNOTICE("Proxy %d:%d %s failed to send message in suggest_diff",
			  proxy->id, proxy->subid, proxy->url);
		if (cs->fd > 0) {
			epoll_ctl(proxy->epfd, EPOLL_CTL_DEL, cs->fd, NULL);
			Close(cs->fd);
		}
	}
	/* We don't care about the response here. It can get filtered out later
	 * if it fails upstream. */
}

/* Upon failing connnect, subscribe, or auth, back off on the next attempt.
 * This function should be called on the parent proxy */
static void proxy_backoff(proxy_instance_t *proxy)
{
	/* Add 5 seconds with each backoff, up to maximum of 1 minute */
	if (proxy->backoff < 60)
		proxy->backoff += 5;
}

static bool proxy_alive(proxy_instance_t *proxi, connsock_t *cs,
			bool pinging)
{
	proxy_instance_t *parent = proxi->parent;
	bool ret = false;

	/* Has this proxy already been reconnected? */
	if (proxi->alive)
		return true;
	if (proxi->disabled)
		return false;

	/* Serialise all send/recvs here with the cs semaphore */
	cksem_wait(&cs->sem);
	/* Check again after grabbing semaphore */
	if (unlikely(proxi->alive)) {
		ret = true;
		goto out;
	}
	if (!extract_sockaddr(proxi->url, &cs->url, &cs->port)) {
		LOGWARNING("Failed to extract address from %s", proxi->url);
		goto out;
	}
	if (!connect_proxy(cs, proxi)) {
		if (!pinging) {
			LOGINFO("Failed to connect to %s:%s in proxy_mode!",
				cs->url, cs->port);
		}
		parent->connect_status = STATUS_FAIL;
		proxy_backoff(parent);
		goto out;
	}
	parent->connect_status = STATUS_SUCCESS;

	if (ckpool.node) {
		if (!node_stratum(cs, proxi)) {
			LOGWARNING("Failed initial node setup to %s:%s !",
				   cs->url, cs->port);
			goto out;
		}
		ret = true;
		goto out;
	}
	if (ckpool.passthrough) {
		if (!passthrough_stratum(cs, proxi)) {
			LOGWARNING("Failed initial passthrough to %s:%s !",
				   cs->url, cs->port);
			goto out;
		}
		ret = true;
		goto out;
	}
	/* Test we can connect, authorise and get stratum information */
	if (!subscribe_stratum(cs, proxi)) {
		if (!pinging) {
			LOGWARNING("Failed initial subscribe to %s:%s !",
				   cs->url, cs->port);
		}
		parent->subscribe_status = STATUS_FAIL;
		proxy_backoff(parent);
		goto out;
	}
	parent->subscribe_status = STATUS_SUCCESS;

	if (!ckpool.passthrough)
		send_subscribe(proxi);
	if (!auth_stratum(cs, proxi)) {
		if (!pinging) {
			LOGWARNING("Failed initial authorise to %s:%s with %s:%s !",
				   cs->url, cs->port, proxi->auth, proxi->pass);
		}
		parent->auth_status = STATUS_FAIL;
		proxy_backoff(parent);
		goto out;
	}
	parent->auth_status = STATUS_SUCCESS;
	proxi->authorised = ret = true;
	parent->backoff = 0;
	if (ckpool.mindiff > 1)
		suggest_diff(cs, proxi);
out:
	if (!ret) {
		send_stratifier_deadproxy(proxi->id, proxi->subid);
		/* Close and invalidate the file handle */
		Close(cs->fd);
	}
	proxi->alive = ret;
	cksem_post(&cs->sem);

	/* Decrease the parent's recruit count after sending the stratifier the
	 * new subscribe so it can get an accurate headroom count before
	 * requesting more proxies. */
	if (ret) {
		proxy_instance_t *parent = proxi->parent;

		if (parent) {
			mutex_lock(&parent->proxy_lock);
			parent->recruit -= proxi->clients_per_proxy;
			if (parent->recruit < 0)
				parent->recruit = 0;
			mutex_unlock(&parent->proxy_lock);
		}
	}

	return ret;
}

static void *proxy_recruit(void *arg)
{
	proxy_instance_t *proxy, *parent = (proxy_instance_t *)arg;
	gdata_t *gdata = ckpool.gdata;
	bool recruit, alive;

	pthread_detach(pthread_self());

	/* We do this in a separate thread so it's okay to sleep here */
	if (parent->backoff)
		sleep(parent->backoff);

retry:
	recruit = false;
	proxy = create_subproxy(gdata, parent, parent->url, parent->baseurl);
	alive = proxy_alive(proxy, &proxy->cs, false);
	if (!alive) {
		LOGNOTICE("Subproxy failed proxy_alive testing");
		store_proxy(gdata, proxy);
	} else
		add_subproxy(parent, proxy);

	mutex_lock(&parent->proxy_lock);
	if (alive && parent->recruit > 0)
		recruit = true;
	else /* Reset so the next request will try again */
		parent->recruit = 0;
	mutex_unlock(&parent->proxy_lock);

	if (recruit)
		goto retry;

	return NULL;
}

static void recruit_subproxies(proxy_instance_t *proxi, const int recruits)
{
	bool recruit = false;
	pthread_t pth;

	mutex_lock(&proxi->proxy_lock);
	if (!proxi->recruit)
		recruit = true;
	if (proxi->recruit < recruits)
		proxi->recruit = recruits;
	mutex_unlock(&proxi->proxy_lock);

	if (recruit)
		create_pthread(&pth, proxy_recruit, proxi);
}

/* Queue up to the requested amount */
static void recruit_subproxy(gdata_t *gdata, const char *buf)
{
	int recruits = 1, id = 0;
	proxy_instance_t *proxy;

	sscanf(buf, "recruit=%d:%d", &id, &recruits);
	proxy = proxy_by_id(gdata, id);
	if (unlikely(!proxy)) {
		LOGNOTICE("Generator failed to find proxy id %d to recruit subproxies",
			  id);
		return;
	}
	recruit_subproxies(proxy, recruits);
}

static void *proxy_reconnect(void *arg)
{
	proxy_instance_t *proxy = (proxy_instance_t *)arg;
	connsock_t *cs = &proxy->cs;

	pthread_detach(pthread_self());
	if (proxy->parent->backoff)
		sleep(proxy->parent->backoff);
	proxy_alive(proxy, cs, true);
	proxy->reconnecting = false;
	return NULL;
}

/* For reconnecting the parent proxy instance async */
static void reconnect_proxy(proxy_instance_t *proxi)
{
	pthread_t pth;

	if (proxi->reconnecting)
		return;
	proxi->reconnecting = true;
	create_pthread(&pth, proxy_reconnect, proxi);
}

/* For receiving messages from an upstream pool to pass downstream. Responsible
 * for setting up the connection and testing pool is live. */
static void *passthrough_recv(void *arg)
{
	proxy_instance_t *proxi = (proxy_instance_t *)arg;
	connsock_t *cs = &proxi->cs;
	bool alive;

	rename_proc("passrecv");

	proxi->parent = proxi;
	if (proxy_alive(proxi, cs, false))
		LOGWARNING("Passthrough proxy %d:%s connection established", proxi->id, proxi->url);
	alive = proxi->alive;

	while (42) {
		float timeout = 5;
		int ret;

		while (!proxy_alive(proxi, cs, true)) {
			alive = false;
			sleep(5);
		}
		if (!alive) {
			reconnect_generator();
			LOGWARNING("Passthrough %d:%s recovered", proxi->id, proxi->url);
			alive = true;
		}

		cksem_wait(&cs->sem);
		ret = read_socket_line(cs, &timeout);
		/* Simply forward the message on, as is, to the connector to
		 * process. Possibly parse parameters sent by upstream pool
		 * here */
		if (likely(ret > 0)) {
			LOGDEBUG("Passthrough recv received upstream msg: %s", cs->buf);
			send_proc(ckpool.connector, cs->buf);
		} else if (ret < 0) {
			/* Read failure */
			LOGWARNING("Passthrough %d:%s failed to read_socket_line in passthrough_recv, attempting reconnect",
				   proxi->id, proxi->url);
			alive = proxi->alive = false;
			Close(cs->fd);
			reconnect_generator();
		} else /* No messages during timeout */
			LOGDEBUG("Passthrough %d:%s no messages received", proxi->id, proxi->url);
		cksem_post(&cs->sem);
	}
	return NULL;
}

static bool subproxies_alive(proxy_instance_t *proxy)
{
	proxy_instance_t *subproxy, *tmp;
	bool ret = false;

	mutex_lock(&proxy->proxy_lock);
	HASH_ITER(sh, proxy->subproxies, subproxy, tmp) {
		if (subproxy->alive) {
			ret = true;
			break;
		}
	}
	mutex_unlock(&proxy->proxy_lock);

	return ret;
}

/* For receiving messages from the upstream proxy, also responsible for setting
 * up the connection and testing it's alive. */
static void *proxy_recv(void *arg)
{
	proxy_instance_t *proxi = (proxy_instance_t *)arg;
	connsock_t *cs = &proxi->cs;
	proxy_instance_t *subproxy;
	gdata_t *gdata = ckpool.gdata;
	struct epoll_event event;
	bool alive;
	int epfd;

	rename_proc("proxyrecv");
	pthread_detach(pthread_self());

	proxi->epfd = epfd = epoll_create1(EPOLL_CLOEXEC);
	if (epfd < 0){
		LOGEMERG("FATAL: Failed to create epoll in proxyrecv");
		return NULL;
	}

	if (proxy_alive(proxi, cs, false))
		LOGWARNING("Proxy %d:%s connection established", proxi->id, proxi->url);

	alive = proxi->alive;

	while (42) {
		bool message = false, hup = false;
		share_msg_t *share, *tmpshare;
		notify_instance_t *ni, *tmp;
		float timeout;
		time_t now;
		int ret;

		subproxy = proxi;
		if (!proxi->alive) {
			reconnect_proxy(proxi);
			while (!subproxies_alive(proxi)) {
				reconnect_proxy(proxi);
				if (alive) {
					reconnect_generator();
					LOGWARNING("Proxy %d:%s failed, attempting reconnect",
						   proxi->id, proxi->url);
					alive = false;
				}
				sleep(5);
			}
		}
		if (!alive) {
			reconnect_generator();
			LOGWARNING("Proxy %d:%s recovered", proxi->id, proxi->url);
			alive = true;
		}

		now = time(NULL);

		/* Age old notifications older than 10 mins old */
		mutex_lock(&gdata->notify_lock);
		HASH_ITER(hh, gdata->notify_instances, ni, tmp) {
			if (HASH_COUNT(gdata->notify_instances) < 3)
				break;
			if (ni->notify_time < now - 600) {
				HASH_DEL(gdata->notify_instances, ni);
				clear_notify(ni);
			}
		}
		mutex_unlock(&gdata->notify_lock);

		/* Similary with shares older than 2 mins without response */
		mutex_lock(&gdata->share_lock);
		HASH_ITER(hh, gdata->shares, share, tmpshare) {
			if (share->submit_time < now - 120) {
				HASH_DEL(gdata->shares, share);
				free(share);
			}
		}
		mutex_unlock(&gdata->share_lock);

		cs = NULL;
		/* If we don't get an update within 10 minutes the upstream pool
		 * has likely stopped responding. */
		ret = epoll_wait(epfd, &event, 1, 600000);
		if (likely(ret > 0)) {
			subproxy = event.data.ptr;
			cs = &subproxy->cs;
			if (!subproxy->alive) {
				cs = NULL;
				continue;
			}

			/* Serialise messages from here once we have a cs by
			 * holding the semaphore. */
			cksem_wait(&cs->sem);
			/* Process any messages before checking for errors in
			 * case a message is sent and then the socket
			 * immediately closed.
			 */
			if (event.events & EPOLLIN) {
				timeout = 30;
				ret = read_socket_line(cs, &timeout);
				/* If we are unable to read anything within 30
				 * seconds at this point after EPOLLIN is set
				 * then the socket is dead. */
				if (ret < 1) {
					LOGNOTICE("Proxy %d:%d %s failed to read_socket_line in proxy_recv",
						  proxi->id, subproxy->subid, subproxy->url);
					hup = true;
				} else {
					message = true;
					timeout = 0;
				}
			}
			if (event.events & (EPOLLHUP | EPOLLERR | EPOLLRDHUP)) {
				LOGNOTICE("Proxy %d:%d %s epoll hangup in proxy_recv",
					  proxi->id, subproxy->subid, subproxy->url);
				hup = true;
			}
		} else {
			LOGNOTICE("Proxy %d:%d %s failed to epoll in proxy_recv",
				  proxi->id, subproxy->subid, subproxy->url);
			hup = true;
		}

		/* Parse any other messages already fully buffered with a zero
		 * timeout. */
		while (message || read_socket_line(cs, &timeout) > 0) {
			message = false;
			timeout = 0;
			/* subproxy may have been recycled here if it is not a
			 * parent and reconnect was issued */
			if (parse_method(subproxy, cs->buf))
				continue;
			/* If it's not a method it should be a share result */
			if (!parse_share(gdata, subproxy, cs->buf)) {
				LOGNOTICE("Proxy %d:%d unhandled stratum message: %s",
					  subproxy->id, subproxy->subid, cs->buf);
			}
		}

		/* Process hangup only after parsing messages */
		if (hup)
			disable_subproxy(gdata, proxi, subproxy);
		if (cs)
			cksem_post(&cs->sem);
	}

	return NULL;
}

/* Thread that handles all received messages from user proxies */
static void *userproxy_recv(void __maybe_unused *arg)
{
	gdata_t *gdata = ckpool.gdata;
	struct epoll_event event;
	int epfd;

	rename_proc("uproxyrecv");
	pthread_detach(pthread_self());

	epfd = epoll_create1(EPOLL_CLOEXEC);
	if (epfd < 0){
		LOGEMERG("FATAL: Failed to create epoll in userproxy_recv");
		return NULL;
	}

	while (42) {
		proxy_instance_t *proxy, *tmpproxy;
		bool message = false, hup = false;
		share_msg_t *share, *tmpshare;
		notify_instance_t *ni, *tmp;
		connsock_t *cs;
		float timeout;
		time_t now;
		int ret;

		mutex_lock(&gdata->lock);
		HASH_ITER(hh, gdata->proxies, proxy, tmpproxy) {
			if (!proxy->global && !proxy->alive) {
				proxy->epfd = epfd;
				reconnect_proxy(proxy);
			}
		}
		mutex_unlock(&gdata->lock);

		ret = epoll_wait(epfd, &event, 1, 1000);
		if (ret < 1) {
			if (likely(!ret))
				continue;
			LOGEMERG("Failed to epoll_wait in userproxy_recv");
			break;
		}
		proxy = event.data.ptr;
		/* Make sure we haven't popped this off before we've finished
		 * subscribe/auth */
		if (unlikely(!proxy->authorised))
			continue;

		now = time(NULL);

		mutex_lock(&gdata->notify_lock);
		HASH_ITER(hh, gdata->notify_instances, ni, tmp) {
			if (HASH_COUNT(gdata->notify_instances) < 3)
				break;
			if (ni->notify_time < now - 600) {
				HASH_DEL(gdata->notify_instances, ni);
				clear_notify(ni);
			}
		}
		mutex_unlock(&gdata->notify_lock);

		/* Similary with shares older than 2 mins without response */
		mutex_lock(&gdata->share_lock);
		HASH_ITER(hh, gdata->shares, share, tmpshare) {
			if (share->submit_time < now - 120) {
				HASH_DEL(gdata->shares, share);
				free(share);
			}
		}
		mutex_unlock(&gdata->share_lock);

		cs = &proxy->cs;

#if 0
		/* Is this needed at all? */
		if (!proxy->alive)
			continue;
#endif

		if ((event.events & (EPOLLHUP | EPOLLERR | EPOLLRDHUP))) {
			LOGNOTICE("Proxy %d:%d %s hangup in userproxy_recv", proxy->id,
				  proxy->subid, proxy->url);
			hup = true;
		}

		if (likely(event.events & EPOLLIN)) {
			timeout = 30;

			cksem_wait(&cs->sem);
			ret = read_socket_line(cs, &timeout);
			/* If we are unable to read anything within 30
			 * seconds at this point after EPOLLIN is set
			 * then the socket is dead. */
			if (ret < 1) {
				LOGNOTICE("Proxy %d:%d %s failed to read_socket_line in userproxy_recv",
					  proxy->id, proxy->subid, proxy->url);
				hup = true;
			} else {
				message = true;
				timeout = 0;
			}
			while (message || (ret = read_socket_line(cs, &timeout)) > 0) {
				message = false;
				timeout = 0;
				/* proxy may have been recycled here if it is not a
				 * parent and reconnect was issued */
				if (parse_method(proxy, cs->buf))
					continue;
				/* If it's not a method it should be a share result */
				if (!parse_share(gdata, proxy, cs->buf)) {
					LOGNOTICE("Proxy %d:%d unhandled stratum message: %s",
						  proxy->id, proxy->subid, cs->buf);
				}
			}
			cksem_post(&cs->sem);
		}

		if (hup) {
			disable_subproxy(gdata, proxy->parent, proxy);
			continue;
		}
	}
	return NULL;
}

static void prepare_proxy(proxy_instance_t *proxi)
{
	proxi->parent = proxi;
	mutex_init(&proxi->proxy_lock);
	add_subproxy(proxi, proxi);
	if (proxi->global)
		create_pthread(&proxi->pth_precv, proxy_recv, proxi);
}

static proxy_instance_t *wait_best_proxy(gdata_t *gdata)
{
	proxy_instance_t *ret = NULL, *proxi, *tmp;
	int retries = 0;

	while (42) {
		mutex_lock(&gdata->lock);
		HASH_ITER(hh, gdata->proxies, proxi, tmp) {
			if (proxi->disabled || !proxi->global)
				continue;
			if (proxi->alive || subproxies_alive(proxi)) {
				if (!ret || proxi->id < ret->id)
					ret = proxi;
			}
		}
		mutex_unlock(&gdata->lock);

		if (ret)
			break;
		/* Send reject message if we are unable to find an active
		 * proxy for more than 5 seconds */
		if (!((retries++) % 5))
			send_proc(ckpool.connector, "reject");
		sleep(1);
	}
	send_proc(ckpool.connector, ret ? "accept" : "reject");
	return ret;
}

static void send_list(gdata_t *gdata, const int sockd)
{
	yyjson_mut_doc *doc = yyjson_mut_doc_new(&ckyyalc);
	yyjson_mut_val *val, *array_val, *root;
	proxy_instance_t *proxy, *tmp;

	array_val = yyjson_mut_arr(doc);

	mutex_lock(&gdata->lock);
	HASH_ITER(hh, gdata->proxies, proxy, tmp) {
		val = yyjson_mut_pack_val(doc, "{si,sb,si,ss,ss,sf,sb,sb,si}",
			"id", proxy->id, "global", proxy->global, "userid", proxy->userid,
			"auth", proxy->auth, "pass", proxy->pass,
			"diff", proxy->diff,
			"disabled", proxy->disabled, "alive", proxy->alive,
			"subproxies", proxy->subproxy_count);
		if (proxy->enonce1) {
			yyjson_mut_obj_add_strcpy(doc, val, "enonce1", proxy->enonce1);
			yyjson_mut_obj_add_int(doc, val, "nonce1len", proxy->nonce1len);
			yyjson_mut_obj_add_int(doc, val, "nonce2len", proxy->nonce2len);
		}
		yyjson_mut_arr_append(array_val, val);
	}
	mutex_unlock(&gdata->lock);

	root = yyjson_mut_pack_val(doc, "{so}", "proxies", array_val);
	yyjson_mut_doc_set_root(doc, root);
	send_api_yyresponse(doc, sockd);
}

static void send_sublist(gdata_t *gdata, const int sockd, const char *buf)
{
	yyjson_mut_doc *doc = yyjson_mut_doc_new(&ckyyalc), *res = NULL;
	yyjson_mut_val *sval, *array_val, *root;
	proxy_instance_t *proxy, *subproxy, *tmp;
	yyjson_doc *val = NULL;
	yyjson_read_err err_val;
	int64_t id;

	array_val = yyjson_mut_arr(doc);

	val = yyjson_read_opts((char *)buf, strlen(buf), 0, NULL, &err_val);
	if (unlikely(!val)) {
		res = yyjson_encode_errormsg(&err_val);
		goto out;
	}
	if (unlikely(!yyjson_obj_get_int64(&id, yyjson_doc_get_root(val), "id"))) {
		res = yyjson_errormsg("Failed to get ID in send_sublist JSON: %s", buf);
		goto out;
	}
	proxy = proxy_by_id(gdata, id);
	if (unlikely(!proxy)) {
		res = yyjson_errormsg("Failed to find proxy %"PRId64" in send_sublist", id);
		goto out;
	}

	mutex_lock(&gdata->lock);
	HASH_ITER(sh, proxy->subproxies, subproxy, tmp) {
		sval = yyjson_mut_pack_val(doc, "{si,ss,ss,sf,sb,sb}",
			"subid", subproxy->id,
			"auth", subproxy->auth, "pass", subproxy->pass,
			"diff", subproxy->diff,
			"disabled", subproxy->disabled, "alive", subproxy->alive);
		if (subproxy->enonce1) {
			yyjson_mut_obj_add_strcpy(doc, sval, "enonce1", subproxy->enonce1);
			yyjson_mut_obj_add_int(doc, sval, "nonce1len", subproxy->nonce1len);
			yyjson_mut_obj_add_int(doc, sval, "nonce2len", subproxy->nonce2len);
		}
		yyjson_mut_arr_append(array_val, sval);
	}
	mutex_unlock(&gdata->lock);

	root = yyjson_mut_pack_val(doc, "{so}", "subproxies", array_val);
	yyjson_mut_doc_set_root(doc, root);
	res = doc;
	doc = NULL;
out:
	if (doc)
		yyjson_mut_doc_free(doc);
	if (val)
		yyjson_doc_free(val);
	send_api_yyresponse(res, sockd);
}

static proxy_instance_t *__add_proxy(gdata_t *gdata, const int num);

static proxy_instance_t *__add_userproxy(gdata_t *gdata, const int id,
					 const int userid, char *url, char *auth, char *pass)
{
	proxy_instance_t *proxy;

	gdata->proxies_generated++;
	proxy = ckzalloc(sizeof(proxy_instance_t));
	proxy->id = id;
	proxy->userid = userid;
	proxy->url = url;
	proxy->baseurl = strdup(url);
	proxy->auth = auth;
	proxy->pass = pass;
	cksem_init(&proxy->cs.sem);
	cksem_post(&proxy->cs.sem);
	HASH_ADD_INT(gdata->proxies, id, proxy);
	return proxy;
}

static void add_userproxy(gdata_t *gdata, const int userid,
			  const char *url, const char *auth, const char *pass)
{
	proxy_instance_t *proxy;
	char *newurl = strdup(url);
	char *newauth = strdup(auth);
	char *newpass = strdup(pass ? pass : "");
	int id;

	mutex_lock(&gdata->lock);
	id = ckpool.proxies++;
	proxy = __add_userproxy(gdata, id, userid, newurl, newauth, newpass);
	mutex_unlock(&gdata->lock);

	LOGWARNING("Adding non global user %s, %d proxy %d:%s", auth, userid, id, url);
	prepare_proxy(proxy);
}

static void parse_addproxy(gdata_t *gdata, const int sockd, const char *buf)
{
	char *url = NULL, *auth = NULL, *pass = NULL;
	yyjson_mut_doc *res = NULL;
	proxy_instance_t *proxy;
	yyjson_val *root = NULL;
	yyjson_doc *val = NULL;
	yyjson_read_err err_val;
	int id, userid;
	bool global;

	val = yyjson_read_opts((char *)buf, strlen(buf), 0, NULL, &err_val);
	if (unlikely(!val)) {
		res = yyjson_encode_errormsg(&err_val);
		goto out;
	}
	root = yyjson_doc_get_root(val);
	yyjson_obj_get_string(&url, root, "url");
	yyjson_obj_get_string(&auth, root, "auth");
	yyjson_obj_get_string(&pass, root, "pass");
	if (yyjson_obj_get_int(&userid, root, "userid"))
		global = false;
	else
		global = true;
	if (unlikely(!url || !auth || !pass)) {
		res = yyjson_errormsg("Failed to decode url/auth/pass in addproxy %s", buf);
		goto out;
	}

	mutex_lock(&gdata->lock);
	id = ckpool.proxies++;
	if (global) {
		ckpool.proxyurl = realloc(ckpool.proxyurl, sizeof(char **) * ckpool.proxies);
		ckpool.proxyauth = realloc(ckpool.proxyauth, sizeof(char **) * ckpool.proxies);
		ckpool.proxypass = realloc(ckpool.proxypass, sizeof(char **) * ckpool.proxies);
		ckpool.proxyurl[id] = url;
		ckpool.proxyauth[id] = auth;
		ckpool.proxypass[id] = pass;
		proxy = __add_proxy(gdata, id);
	} else
		proxy = __add_userproxy(gdata, id, userid, url, auth, pass);
	mutex_unlock(&gdata->lock);

	if (global)
		LOGNOTICE("Adding global proxy %d:%s", id, proxy->url);
	else
		LOGNOTICE("Adding user %d proxy %d:%s", userid, id, proxy->url);
	prepare_proxy(proxy);
	if (global) {
		res = yyjson_mut_pack("{si,ss,ss,ss}",
			"id", proxy->id, "url", url, "auth", auth, "pass", pass);
	} else {
		res = yyjson_mut_pack("{si,ss,ss,ss,si}",
			"id", proxy->id, "url", url, "auth", auth, "pass", pass,
			"userid", proxy->userid);
	}
out:
	if (val)
		yyjson_doc_free(val);
	send_api_yyresponse(res, sockd);
}

static void delete_proxy(gdata_t *gdata, proxy_instance_t *proxy)
{
	proxy_instance_t *subproxy;

	/* Remove the proxy from the master list first */
	mutex_lock(&gdata->lock);
	HASH_DEL(gdata->proxies, proxy);
	/* Disable all its threads */
	pthread_cancel(proxy->pth_precv);
	close_proxy_socket(proxy, proxy);
	mutex_unlock(&gdata->lock);

	/* Recycle all its subproxies */
	do {
		mutex_lock(&proxy->proxy_lock);
		subproxy = proxy->subproxies;
		if (subproxy)
			HASH_DELETE(sh, proxy->subproxies, subproxy);
		mutex_unlock(&proxy->proxy_lock);

		if (subproxy) {
			close_proxy_socket(proxy, subproxy);
			send_stratifier_delproxy(subproxy->id, subproxy->subid);
			if (proxy != subproxy)
				store_proxy(gdata, subproxy);
		}
	} while (subproxy);

	/* Recycle the proxy itself */
	store_proxy(gdata, proxy);
}

static void parse_delproxy(gdata_t *gdata, const int sockd, const char *buf)
{
	yyjson_mut_doc *res = NULL;
	proxy_instance_t *proxy;
	yyjson_doc *val = NULL;
	yyjson_read_err err_val;
	int id = -1;

	val = yyjson_read_opts((char *)buf, strlen(buf), 0, NULL, &err_val);
	if (unlikely(!val)) {
		res = yyjson_encode_errormsg(&err_val);
		goto out;
	}
	yyjson_obj_get_int(&id, yyjson_doc_get_root(val), "id");
	proxy = proxy_by_id(gdata, id);
	if (!proxy) {
		res = yyjson_errormsg("Proxy id %d not found", id);
		goto out;
	}
	res = yyjson_mut_pack("{si,ss,ss,ss,ss}", "id", proxy->id, "url", proxy->url,
			      "baseurl", proxy->baseurl,"auth", proxy->auth, "pass", proxy->pass);

	LOGNOTICE("Deleting proxy %d:%s", proxy->id, proxy->url);
	delete_proxy(gdata, proxy);
out:
	if (val)
		yyjson_doc_free(val);
	send_api_yyresponse(res, sockd);
}

static void parse_ableproxy(gdata_t *gdata, const int sockd, const char *buf, bool disable)
{
	yyjson_mut_doc *res = NULL;
	proxy_instance_t *proxy;
	yyjson_doc *val = NULL;
	yyjson_read_err err_val;
	int id = -1;

	val = yyjson_read_opts((char *)buf, strlen(buf), 0, NULL, &err_val);
	if (unlikely(!val)) {
		res = yyjson_encode_errormsg(&err_val);
		goto out;
	}
	yyjson_obj_get_int(&id, yyjson_doc_get_root(val), "id");
	proxy = proxy_by_id(gdata, id);
	if (!proxy) {
		res = yyjson_errormsg("Proxy id %d not found", id);
		goto out;
	}
	res = yyjson_mut_pack("{si,ss, ss,ss,ss}", "id", proxy->id, "url", proxy->url,
			      "baseurl", proxy->baseurl,"auth", proxy->auth, "pass", proxy->pass);
	if (proxy->disabled != disable) {
		proxy->disabled = disable;
		LOGNOTICE("%sabling proxy %d:%s", disable ? "Dis" : "En", id, proxy->url);
	}
	if (disable) {
		/* Set disabled bool here in case this is a parent proxy */
		proxy->disabled = true;
		disable_subproxy(gdata, proxy, proxy);
	} else
		reconnect_proxy(proxy);
out:
	if (val)
		yyjson_doc_free(val);
	send_api_yyresponse(res, sockd);
}

static void send_stats(gdata_t *gdata, const int sockd)
{
	yyjson_mut_doc *doc = yyjson_mut_doc_new(&ckyyalc);
	yyjson_mut_val *root = yyjson_mut_obj(doc), *subval;
	int total_objects, objects;
	int64_t generated, memsize;
	proxy_instance_t *proxy;
	stratum_msg_t *msg;

	yyjson_mut_doc_set_root(doc, root);

	mutex_lock(&gdata->lock);
	objects = HASH_COUNT(gdata->proxies);
	memsize = SAFE_HASH_OVERHEAD(gdata->proxies) + sizeof(proxy_instance_t) * objects;
	generated = gdata->proxies_generated;
	subval = yyjson_mut_pack_val(doc, "{si,sI,sI}", "count", objects, "memory", memsize, "generated", generated);
	yyjson_mut_obj_add_val(doc, root, "proxies", subval);

	DL_COUNT(gdata->dead_proxies, proxy, objects);
	memsize = sizeof(proxy_instance_t) * objects;
	subval = yyjson_mut_pack_val(doc, "{si,sI}", "count", objects, "memory", memsize);
	yyjson_mut_obj_add_val(doc, root, "dead_proxies", subval);

	total_objects = memsize = 0;
	for (proxy = gdata->proxies; proxy; proxy=proxy->hh.next) {
		mutex_lock(&proxy->proxy_lock);
		total_objects += objects = HASH_COUNT(proxy->subproxies);
		memsize += SAFE_HASH_OVERHEAD(proxy->subproxies) + sizeof(proxy_instance_t) * objects;
		mutex_unlock(&proxy->proxy_lock);
	}
	generated = gdata->subproxies_generated;
	mutex_unlock(&gdata->lock);

	subval = yyjson_mut_pack_val(doc, "{si,sI,sI}", "count", total_objects, "memory", memsize, "generated", generated);
	yyjson_mut_obj_add_val(doc, root, "subproxies", subval);

	mutex_lock(&gdata->notify_lock);
	objects = HASH_COUNT(gdata->notify_instances);
	memsize = SAFE_HASH_OVERHEAD(gdata->notify_instances) + sizeof(notify_instance_t) * objects;
	generated = gdata->proxy_notify_id;
	mutex_unlock(&gdata->notify_lock);

	subval = yyjson_mut_pack_val(doc, "{si,sI,sI}", "count", objects, "memory", memsize, "generated", generated);
	yyjson_mut_obj_add_val(doc, root, "notifies", subval);

	mutex_lock(&gdata->share_lock);
	objects = HASH_COUNT(gdata->shares);
	memsize = SAFE_HASH_OVERHEAD(gdata->shares) + sizeof(share_msg_t) * objects;
	generated = gdata->share_id;
	mutex_unlock(&gdata->share_lock);

	subval = yyjson_mut_pack_val(doc, "{si,sI,sI}", "count", objects, "memory", memsize, "generated", generated);
	yyjson_mut_obj_add_val(doc, root, "shares", subval);

	mutex_lock(&gdata->psend_lock);
	DL_COUNT(gdata->psends, msg, objects);
	generated = gdata->psends_generated;
	mutex_unlock(&gdata->psend_lock);

	memsize = sizeof(stratum_msg_t) * objects;
	subval = yyjson_mut_pack_val(doc, "{si,sI,sI}", "count", objects, "memory", memsize, "generated", generated);
	yyjson_mut_obj_add_val(doc, root, "psends", subval);

	send_api_yyresponse(doc, sockd);
}

/* Entered with parent proxy locked */
static yyjson_mut_val *__proxystats(yyjson_mut_doc *doc, proxy_instance_t *proxy,
				    proxy_instance_t *parent, bool discrete)
{
	yyjson_mut_val *val = yyjson_mut_obj(doc);

	/* Opportunity to update hashrate just before we report it without
	 * needing to check on idle proxies regularly */
	__decay_proxy(proxy, parent, 0);

	yyjson_mut_obj_add_int(doc, val, "id", proxy->id);
	yyjson_mut_obj_add_int(doc, val, "userid", proxy->userid);
	yyjson_mut_obj_add_strcpy(doc, val, "baseurl", proxy->baseurl);
	yyjson_mut_obj_add_strcpy(doc, val, "url", proxy->url);
	yyjson_mut_obj_add_strcpy(doc, val, "auth", proxy->auth);
	yyjson_mut_obj_add_strcpy(doc, val, "pass", proxy->pass);
	yyjson_mut_obj_add_strcpy(doc, val, "enonce1", proxy->enonce1 ? proxy->enonce1 : "");
	yyjson_mut_obj_add_int(doc, val, "nonce1len", proxy->nonce1len);
	yyjson_mut_obj_add_int(doc, val, "nonce2len", proxy->nonce2len);
	yyjson_mut_obj_add_real(doc, val, "diff", proxy->diff);
	if (parent_proxy(proxy)) {
		yyjson_mut_obj_add_real(doc, val, "total_accepted", proxy->total_accepted);
		yyjson_mut_obj_add_real(doc, val, "total_rejected", proxy->total_rejected);
		yyjson_mut_obj_add_int(doc, val, "subproxies", proxy->subproxy_count);
		yyjson_mut_obj_add_real(doc, val, "tdsps1", proxy->tdsps1);
		yyjson_mut_obj_add_real(doc, val, "tdsps5", proxy->tdsps5);
		yyjson_mut_obj_add_real(doc, val, "tdsps60", proxy->tdsps60);
		yyjson_mut_obj_add_real(doc, val, "tdsps1440", proxy->tdsps1440);
	}
	if (discrete) {
		yyjson_mut_obj_add_real(doc, val, "dsps1", proxy->dsps1);
		yyjson_mut_obj_add_real(doc, val, "dsps5", proxy->dsps5);
		yyjson_mut_obj_add_real(doc, val, "dsps60", proxy->dsps60);
		yyjson_mut_obj_add_real(doc, val, "dsps1440", proxy->dsps1440);
		yyjson_mut_obj_add_real(doc, val, "accepted", proxy->diff_accepted);
		yyjson_mut_obj_add_real(doc, val, "rejected", proxy->diff_rejected);
	}
	yyjson_mut_obj_add_strcpy(doc, val, "connect", proxy_status[parent->connect_status]);
	yyjson_mut_obj_add_strcpy(doc, val, "subscribe", proxy_status[parent->subscribe_status]);
	yyjson_mut_obj_add_strcpy(doc, val, "authorise", proxy_status[parent->auth_status]);
	yyjson_mut_obj_add_int(doc, val, "backoff", parent->backoff);
	yyjson_mut_obj_add_int(doc, val, "lastshare", proxy->last_share.tv_sec);
	yyjson_mut_obj_add_bool(doc, val, "global", proxy->global);
	yyjson_mut_obj_add_bool(doc, val, "disabled", proxy->disabled);
	yyjson_mut_obj_add_bool(doc, val, "alive", proxy->alive);
	yyjson_mut_obj_add_int(doc, val, "maxclients", proxy->clients_per_proxy);

	return val;
}

static yyjson_mut_val *proxystats(yyjson_mut_doc *doc, proxy_instance_t *proxy, bool discrete)
{
	proxy_instance_t *parent = proxy->parent;
	yyjson_mut_val *val;

	mutex_lock(&parent->proxy_lock);
	val = __proxystats(doc, proxy, parent, discrete);
	mutex_unlock(&parent->proxy_lock);

	return val;
}

static yyjson_mut_doc *all_proxystats(gdata_t *gdata)
{
	yyjson_mut_doc *doc = yyjson_mut_doc_new(&ckyyalc);
	yyjson_mut_val *root, *arr_val = yyjson_mut_arr(doc);
	proxy_instance_t *proxy, *tmp;

	mutex_lock(&gdata->lock);
	HASH_ITER(hh, gdata->proxies, proxy, tmp) {
		mutex_unlock(&gdata->lock);
		yyjson_mut_arr_append(arr_val, proxystats(doc, proxy, false));
		mutex_lock(&gdata->lock);
	}
	mutex_unlock(&gdata->lock);

	root = yyjson_mut_pack_val(doc, "{so}", "proxy", arr_val);
	yyjson_mut_doc_set_root(doc, root);
	return doc;
}

static void parse_proxystats(gdata_t *gdata, const int sockd, const char *buf)
{
	yyjson_mut_doc *res = NULL;
	proxy_instance_t *proxy;
	yyjson_val *root = NULL;
	yyjson_doc *val = NULL;
	yyjson_read_err err_val;
	bool totals = false;
	int id, subid = 0;

	val = yyjson_read_opts((char *)buf, strlen(buf), 0, NULL, &err_val);
	if (unlikely(!val)) {
		res = all_proxystats(gdata);
		goto out_noval;
	}
	root = yyjson_doc_get_root(val);
	if (!yyjson_obj_get_int(&id, root, "id")) {
		res = all_proxystats(gdata);
		goto out;
	}
	if (!yyjson_obj_get_int(&subid, root, "subid"))
		totals = true;
	proxy = proxy_by_id(gdata, id);
	if (!proxy) {
		res = yyjson_errormsg("Proxy id %d not found", id);
		goto out;
	}
	if (!totals)
		proxy = subproxy_by_id(proxy, subid);
	if (!proxy) {
		res = yyjson_errormsg("Proxy id %d:%d not found", id, subid);
		goto out;
	}
	res = yyjson_mut_doc_new(&ckyyalc);
	yyjson_mut_doc_set_root(res, proxystats(res, proxy, true));
out:
	yyjson_doc_free(val);
out_noval:
	send_api_yyresponse(res, sockd);
}

static void send_subproxystats(gdata_t *gdata, const int sockd)
{
	yyjson_mut_doc *doc = yyjson_mut_doc_new(&ckyyalc);
	yyjson_mut_val *root, *arr_val = yyjson_mut_arr(doc);
	proxy_instance_t *parent, *tmp;

	mutex_lock(&gdata->lock);
	HASH_ITER(hh, gdata->proxies, parent, tmp) {
		yyjson_mut_val *val, *subarr_val = yyjson_mut_arr(doc);
		proxy_instance_t *subproxy, *subtmp;

		mutex_unlock(&gdata->lock);

		mutex_lock(&parent->proxy_lock);
		HASH_ITER(sh, parent->subproxies, subproxy, subtmp) {
			val = __proxystats(doc, subproxy, parent, true);
			yyjson_mut_obj_add_int(doc, val, "subid", subproxy->subid);
			yyjson_mut_arr_append(subarr_val, val);
		}
		mutex_unlock(&parent->proxy_lock);

		val = yyjson_mut_pack_val(doc, "{si,so}",
					  "id", parent->id,
					  "subproxy", subarr_val);
		yyjson_mut_arr_append(arr_val, val);
		mutex_lock(&gdata->lock);
	}
	mutex_unlock(&gdata->lock);

	root = yyjson_mut_pack_val(doc, "{so}", "proxy", arr_val);
	yyjson_mut_doc_set_root(doc, root);
	send_api_yyresponse(doc, sockd);
}

static void parse_globaluser(gdata_t *gdata, const char *buf)
{
	char *url, *username, *pass = strdupa(buf);
	int userid = -1, proxyid = -1;
	proxy_instance_t *proxy, *tmp;
	int64_t clientid = -1;
	bool found = false;

	sscanf(buf, "%d:%d:%"PRId64":%s", &proxyid, &userid, &clientid, pass);
	if (unlikely(clientid < 0 || userid < 0 || proxyid < 0)) {
		LOGWARNING("Failed to parse_globaluser ids from command %s", buf);
		return;
	}
	username = strsep(&pass, ",");
	if (unlikely(!username)) {
		LOGWARNING("Failed to parse_globaluser username from command %s", buf);
		return;
	}

	LOGDEBUG("Checking userproxy proxy %d user %d:%"PRId64" worker %s pass %s",
		 proxyid, userid, clientid, username, pass);

	if (unlikely(proxyid >= ckpool.proxies)) {
		LOGWARNING("Trying to find non-existent proxy id %d in parse_globaluser", proxyid);
		return;
	}

	mutex_lock(&gdata->lock);
	url = ckpool.proxyurl[proxyid];
	HASH_ITER(hh, gdata->proxies, proxy, tmp) {
		if (!strcmp(proxy->auth, username)) {
			found = true;
			break;
		}
	}
	mutex_unlock(&gdata->lock);

	if (found)
		return;
	add_userproxy(gdata, userid, url, username, pass);
}

static void proxy_loop(proc_instance_t *pi)
{
	proxy_instance_t *proxi = NULL, *cproxy;
	server_instance_t *si = NULL, *old_si;
	gdata_t *gdata = ckpool.gdata;
	unix_msg_t *umsg = NULL;
	connsock_t *cs = NULL;
	char *buf = NULL;

reconnect:
	clear_unix_msg(&umsg);

	if (ckpool.node) {
		old_si = si;
		si = live_server(gdata);
		if (!si)
			goto out;
		cs = &si->cs;
		if (!old_si)
			LOGWARNING("Connected to bitcoind: %s:%s", cs->url, cs->port);
		else if (si != old_si)
			LOGWARNING("Failed over to bitcoind: %s:%s", cs->url, cs->port);
	}

	/* This does not necessarily mean we reconnect, but a change has
	 * occurred and we need to reexamine the proxies. */
	cproxy = wait_best_proxy(gdata);
	if (!cproxy)
		goto out;
	if (proxi != cproxy) {
		gdata->current_proxy = proxi = cproxy;
		LOGWARNING("Successfully connected to pool %d %s as proxy%s",
			   proxi->id, proxi->url, ckpool.passthrough ? " in passthrough mode" : "");
	}

	if (unlikely(!ckpool.generator_ready)) {
		ckpool.generator_ready = true;
		LOGWARNING("%s generator ready", ckpool.name);
	}
retry:
	clear_unix_msg(&umsg);
	do {
		umsg = get_unix_msg(pi);
	} while (!umsg);

	buf = umsg->buf;
	LOGDEBUG("Proxy received request: %s", buf);
	if (cmdmatch(buf, "stats")) {
		send_stats(gdata, umsg->sockd);
	} else if (cmdmatch(buf, "list")) {
		send_list(gdata, umsg->sockd);
	} else if (cmdmatch(buf, "sublist")) {
		send_sublist(gdata, umsg->sockd, buf + 8);
	} else if (cmdmatch(buf, "addproxy")) {
		parse_addproxy(gdata, umsg->sockd, buf + 9);
	} else if (cmdmatch(buf, "delproxy")) {
		parse_delproxy(gdata, umsg->sockd, buf + 9);
	} else if (cmdmatch(buf, "enableproxy")) {
		parse_ableproxy(gdata, umsg->sockd, buf + 12, false);
	} else if (cmdmatch(buf, "disableproxy")) {
		parse_ableproxy(gdata, umsg->sockd, buf + 13, true);
	} else if (cmdmatch(buf, "proxystats")) {
		parse_proxystats(gdata, umsg->sockd, buf + 11);
	} else if (cmdmatch(buf, "subproxystats")) {
		send_subproxystats(gdata, umsg->sockd);
	} else if (cmdmatch(buf, "globaluser")) {
		parse_globaluser(gdata, buf + 11);
	} else if (cmdmatch(buf, "reconnect")) {
		goto reconnect;
	} else if (cmdmatch(buf, "submitblock:")) {
		char blockmsg[80];
		bool ret;

		LOGNOTICE("Submitting likely block solve share from upstream pool");
		ret = submit_block(cs, buf + 12 + 64 + 1);
		memset(buf + 12 + 64, 0, 1);
		sprintf(blockmsg, "%sblock:%s", ret ? "" : "no", buf + 12);
		send_proc(ckpool.stratifier, blockmsg);
	} else if (cmdmatch(buf, "submittxn:")) {
		if (unlikely(strlen(buf) < 11)) {
			LOGWARNING("Got zero length submittxn");
			goto retry;
		}
		submit_txn(cs, buf + 10);
	} else if (cmdmatch(buf, "loglevel")) {
		sscanf(buf, "loglevel=%d", &ckpool.loglevel);
	} else if (cmdmatch(buf, "ping")) {
		LOGDEBUG("Proxy received ping request");
		send_unix_msg(umsg->sockd, "pong");
	} else if (cmdmatch(buf, "recruit")) {
		recruit_subproxy(gdata, buf);
	} else if (cmdmatch(buf, "dropproxy")) {
		drop_proxy(gdata, buf);
	} else {
		LOGWARNING("Generator received unrecognised message: %s", buf);
	}
	goto retry;
out:
	return;
}

/* Check which servers are alive, maintaining a connection with them and
 * reconnect if a higher priority one is available. */
static void *server_watchdog(void __maybe_unused *arg)
{
	gdata_t *gdata = ckpool.gdata;

	rename_proc("swatchdog");

	pthread_detach(pthread_self());

	while (42) {
		server_instance_t *best = NULL;
		ts_t timer_t;
		int i;

		cksleep_prepare_r(&timer_t);
		for (i = 0; i < ckpool.btcds; i++) {
			server_instance_t *si  = ckpool.servers[i];

			/* Have we reached the current server? */
			if (server_alive(si, true) && !best)
				best = si;
		}
		if (best && best != gdata->current_si)
			send_proc(ckpool.generator, "reconnect");
		cksleep_ms_r(&timer_t, 5000);
	}
	return NULL;
}

static void setup_servers(void)
{
	pthread_t pth_watchdog;
	int i;

	ckpool.servers = ckalloc(sizeof(server_instance_t *) * ckpool.btcds);
	for (i = 0; i < ckpool.btcds; i++) {
		server_instance_t *si;
		connsock_t *cs;

		ckpool.servers[i] = ckzalloc(sizeof(server_instance_t));
		si = ckpool.servers[i];
		si->url = ckpool.btcdurl[i];
		si->auth = ckpool.btcdauth[i];
		si->pass = ckpool.btcdpass[i];
		si->notify = ckpool.btcdnotify[i];
		si->id = i;
		cs = &si->cs;
		cksem_init(&cs->sem);
		cksem_post(&cs->sem);
	}

	create_pthread(&pth_watchdog, server_watchdog, NULL);
}

static void server_mode(proc_instance_t *pi)
{
	int i;

	setup_servers();

	gen_loop(pi);

	for (i = 0; i < ckpool.btcds; i++) {
		server_instance_t *si = ckpool.servers[i];

		kill_server(si);
		dealloc(si);
	}
	dealloc(ckpool.servers);
}

static proxy_instance_t *__add_proxy(gdata_t *gdata, const int id)
{
	proxy_instance_t *proxy;

	gdata->proxies_generated++;
	proxy = ckzalloc(sizeof(proxy_instance_t));
	proxy->id = id;
	proxy->url = strdup(ckpool.proxyurl[id]);
	proxy->baseurl = strdup(proxy->url);
	proxy->auth = strdup(ckpool.proxyauth[id]);
	if (ckpool.proxypass[id])
		proxy->pass = strdup(ckpool.proxypass[id]);
	else
		proxy->pass = strdup("");
	HASH_ADD_INT(gdata->proxies, id, proxy);
	proxy->global = true;
	cksem_init(&proxy->cs.sem);
	cksem_post(&proxy->cs.sem);
	return proxy;
}

static void proxy_mode(proc_instance_t *pi)
{
	gdata_t *gdata = ckpool.gdata;
	proxy_instance_t *proxy;
	int i;

	mutex_init(&gdata->lock);
	mutex_init(&gdata->notify_lock);
	mutex_init(&gdata->share_lock);

	if (ckpool.node)
		setup_servers();

	/* Create all our proxy structures and pointers */
	for (i = 0; i < ckpool.proxies; i++) {
		proxy = __add_proxy(gdata, i);
		if (ckpool.passthrough) {
			create_pthread(&proxy->pth_precv, passthrough_recv, proxy);
			proxy->passsends = create_ckmsgq("passsend", &passthrough_send);
		} else {
			mutex_init(&gdata->psend_lock);
			cond_init(&gdata->psend_cond);
			prepare_proxy(proxy);
			create_pthread(&gdata->pth_uprecv, userproxy_recv, NULL);
			create_pthread(&gdata->pth_psend, proxy_send, NULL);
		}
	}

	proxy_loop(pi);
}

void *generator(void *arg)
{
	proc_instance_t *pi = (proc_instance_t *)arg;
	gdata_t *gdata;

	rename_proc(pi->processname);
	LOGWARNING("%s generator starting", ckpool.name);
	gdata = ckzalloc(sizeof(gdata_t));
	ckpool.gdata = gdata;

	if (ckpool.proxy) {
		/* Wait for the stratifier to be ready for us */
		while (!ckpool.stratifier_ready)
			cksleep_ms(10);
		proxy_mode(pi);
	} else
		server_mode(pi);
	/* We should never get here unless there's a fatal error */
	LOGEMERG("Generator failure, shutting down");
	exit(1);
	return NULL;
}
