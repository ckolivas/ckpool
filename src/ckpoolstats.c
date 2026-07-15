/*
 * Copyright 2026 Con Kolivas
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 3 of the License, or (at your option)
 * any later version.  See COPYING for more details.
 */
#define _GNU_SOURCE

#include <stdlib.h>
#include <stdio.h>
#include <sys/stat.h>
#include <dirent.h>
#include <unistd.h>

#include "libckpool.h"
#include "uthash.h"
#include "yyjson.h"
#include "yyjson_util.h"

#define log(fmt, ...) do { \
	printf(fmt, ##__VA_ARGS__); \
	printf("\n"); \
	fflush(stdout); \
} while(0)

#define logerr(fmt, ...) do { \
	fprintf(stderr, fmt, ##__VA_ARGS__); \
	fprintf(stderr, "\n"); \
	fflush(stderr); \
} while(0)

#define fail(fmt, ...) do { \
	fprintf(stderr, fmt, ##__VA_ARGS__); \
	fprintf(stderr, "\n"); \
	fflush(stderr); \
	exit(1); \
} while(0)

typedef struct {
	int64_t runtime;
	int64_t lastupdate;
	int64_t users;
	int64_t workers;
	int64_t idle;
	int64_t disconnected;
} pstats_t;

typedef struct {
	int hashrate1m;
	int hashrate5m;
	int hashrate15m;
	int hashrate1hr;
	int hashrate6hr;
	int hashrate1d;
	int hashrate7d;
} dsps_t;

typedef struct {
	double diff;
	double sps1m;
	double sps5m;
	double sps15m;
	double sps1h;
	int64_t accepted;
	int64_t rejected;
	int64_t bestshare;
} sps_t;

/* Global combined stats */
pstats_t allpstats;
dsps_t alldsps;
sps_t allsps;

typedef struct {
	UT_hash_handle hh;

	char workername[128];
	yyjson_mut_val *json;
} worker_t;

typedef struct {
	UT_hash_handle hh;

	char username[128];
	/* The document owning this user's json tree; all values combined into
	 * it are copied in so it can be freed/written independently. */
	yyjson_mut_doc *doc;
	yyjson_mut_val *json;
	worker_t *workers;
} user_t;

user_t *users;

/* Parse a JSON string into a mutable document (so it can be modified and
 * written back). Returns NULL on failure. */
static yyjson_mut_doc *parse_json(const char *str)
{
	yyjson_doc *idoc = yyjson_read(str, strlen(str), 0);
	yyjson_mut_doc *doc;

	if (!idoc)
		return NULL;
	doc = yyjson_doc_mut_copy(idoc, &ckyyalc);
	yyjson_doc_free(idoc);
	return doc;
}

/* As parse_json but reading from a file path. */
static yyjson_mut_doc *read_json_file(const char *path)
{
	yyjson_doc *idoc = yyjson_read_file(path, 0, NULL, NULL);
	yyjson_mut_doc *doc;

	if (!idoc)
		return NULL;
	doc = yyjson_doc_mut_copy(idoc, &ckyyalc);
	yyjson_doc_free(idoc);
	return doc;
}

int64_t json_get_int64(int64_t *store, yyjson_mut_val *val, const char *res)
{
	yyjson_mut_val *entry = yyjson_mut_obj_get(val, res);
	*store = 0;

	if (!entry) {
		LOGDEBUG("Json did not find entry %s", res);
		goto out;
	}
	if (!yyjson_mut_is_int(entry)) {
		LOGINFO("Json entry %s is not an integer", res);
		goto out;
	}
	*store = yyjson_mut_get_sint(entry);
	LOGDEBUG("Json found entry %s: %"PRId64, res, *store);
out:
	return *store;
}

double json_get_double(double *store, yyjson_mut_val *val, const char *res)
{
	yyjson_mut_val *entry = yyjson_mut_obj_get(val, res);
	*store = 0;

	if (!entry) {
		LOGDEBUG("Json did not find entry %s", res);
		goto out;
	}
	if (!yyjson_mut_is_real(entry)) {
		LOGWARNING("Json entry %s is not a double", res);
		goto out;
	}
	*store = yyjson_mut_get_real(entry);
	LOGDEBUG("Json found entry %s: %f", res, *store);
out:
	return *store;
}

const double nonces = 4294967296;

bool json_get_string(char **store, yyjson_mut_val *entry, const char *res)
{
	bool ret = false;
	const char *buf;

	*store = NULL;
	if (!entry || yyjson_mut_is_null(entry)) {
		LOGDEBUG("Json did not find entry %s", res);
		goto out;
	}
	if (!yyjson_mut_is_str(entry)) {
		LOGWARNING("Json entry %s is not a string", res);
		goto out;
	}
	buf = yyjson_mut_get_str(entry);
	LOGDEBUG("Json found entry %s: %s", res, buf);
	*store = strdup(buf);
	ret = true;
out:
	return ret;
}

/* Fallthrough intentional */
double dsps_from_key(yyjson_mut_val *sval, const char *key)
{
	char *string, *endptr;
	double ret = 0;
	yyjson_mut_val *val;

	val = yyjson_mut_obj_get(sval, key);
	json_get_string(&string, val, key);
	if (!string)
		return ret;
	ret = strtod(string, &endptr) / nonces;
	if (endptr) {
		switch (endptr[0]) {
			case 'E':
				ret *= (double)1000;
			case 'P':
				ret *= (double)1000;
			case 'T':
				ret *= (double)1000;
			case 'G':
				ret *= (double)1000;
			case 'M':
				ret *= (double)1000;
			case 'K':
				ret *= (double)1000;
			default:
				break;
		}
	}
	free(string);
	return ret;
}

void read_poolstats(FILE *fp)
{
	char *s = alloca(4096), *pstats, *dsps, *sps;
	pstats_t poolpstats = {};
	sps_t poolsps = {};
	yyjson_mut_doc *doc;
	yyjson_mut_val *val;
	int ret;

	memset(s, 0, 4096);
	ret = fread(s, 1, 4095, fp);
	if (ret < 1 || !strlen(s))
		fail("No string to read in pool logfile");

	/* Strip out end of line terminators */
	pstats = strsep(&s, "\n");
	dsps = strsep(&s, "\n");
	sps = strsep(&s, "\n");
	if (!s)
		fail("Failed to find EOL in pool logfile");
	doc = parse_json(pstats);
	if (!doc)
		fail("Failed to json decode pstats line from pool logfile: %s", pstats);
	val = yyjson_mut_doc_get_root(doc);
	json_get_int64(&poolpstats.runtime, val, "runtime");
	json_get_int64(&poolpstats.lastupdate, val, "lastupdate");
	allpstats.users += json_get_int64(&poolpstats.users, val, "Users");
	allpstats.workers += json_get_int64(&poolpstats.workers, val, "Workers");
	allpstats.idle += json_get_int64(&poolpstats.idle, val, "Idle");
	allpstats.disconnected += json_get_int64(&poolpstats.disconnected, val, "Disconnected");
	yyjson_mut_doc_free(doc);

	/* Pessimise these two values from worst stats */
	if (!allpstats.runtime || allpstats.runtime > poolpstats.runtime)
		allpstats.runtime = poolpstats.runtime;
	if (!allpstats.lastupdate || allpstats.lastupdate > poolpstats.lastupdate)
		allpstats.lastupdate = poolpstats.lastupdate;

	doc = parse_json(dsps);
	if (!doc)
		fail("Failed to json decode dsps line from pool logfile: %s", sps);
	val = yyjson_mut_doc_get_root(doc);
	alldsps.hashrate1m += dsps_from_key(val, "hashrate1m");
	alldsps.hashrate5m += dsps_from_key(val, "hashrate5m");
	alldsps.hashrate15m += dsps_from_key(val, "hashrate15m");
	alldsps.hashrate1hr += dsps_from_key(val, "hashrate1hr");
	alldsps.hashrate6hr += dsps_from_key(val, "hashrate6hr");
	alldsps.hashrate1d += dsps_from_key(val, "hashrate1d");
	alldsps.hashrate7d += dsps_from_key(val, "hashrate7d");
	yyjson_mut_doc_free(doc);

	doc = parse_json(sps);
	if (!doc)
		fail("Failed to json decode sps line from pool logfile: %s", dsps);
	val = yyjson_mut_doc_get_root(doc);
	json_get_double(&poolsps.diff, val , "diff");
	if (poolsps.diff > allsps.diff)
		allsps.diff = poolsps.diff;
	allsps.sps1m += json_get_double(&poolsps.sps1m, val, "SPS1m");
	allsps.sps5m += json_get_double(&poolsps.sps5m, val, "SPS5m");
	allsps.sps15m += json_get_double(&poolsps.sps15m, val, "SPS15m");
	allsps.sps1h += json_get_double(&poolsps.sps1h, val, "SPS1h");
	allsps.accepted += json_get_int64(&poolsps.accepted, val, "accepted");
	allsps.rejected += json_get_int64(&poolsps.rejected, val, "rejected");
	json_get_int64(&poolsps.bestshare, val, "bestshare");
	if (poolsps.bestshare > allsps.bestshare)
		allsps.bestshare = poolsps.bestshare;
	yyjson_mut_doc_free(doc);
}

static void add_hashrates(yyjson_mut_doc *doc, yyjson_mut_val *sval, yyjson_mut_val *val, const char *key)
{
	double ghs, dval = dsps_from_key(sval, key);
	char suffix[16];

	dval += dsps_from_key(val, key);
	ghs = dval * nonces;
	suffix_string(ghs, suffix, 16, 0);
	yyjson_mut_obj_put(sval, yyjson_mut_strcpy(doc, key), yyjson_mut_strcpy(doc, suffix));
}

static void set_maxint(yyjson_mut_doc *doc, yyjson_mut_val *sval, yyjson_mut_val *val, const char *key)
{
	int64_t val64, newval64;

	json_get_int64(&val64, sval, key);
	json_get_int64(&newval64, val, key);
	if (newval64 > val64)
		yyjson_mut_obj_put(sval, yyjson_mut_strcpy(doc, key), yyjson_mut_int(doc, newval64));
}

static void set_minint(yyjson_mut_doc *doc, yyjson_mut_val *sval, yyjson_mut_val *val, const char *key)
{
	int64_t val64, newval64;

	json_get_int64(&val64, sval, key);
	json_get_int64(&newval64, val, key);
	if (newval64 < val64)
		yyjson_mut_obj_put(sval, yyjson_mut_strcpy(doc, key), yyjson_mut_int(doc, newval64));
}

static void add_int(yyjson_mut_doc *doc, yyjson_mut_val *sval, yyjson_mut_val *val, const char *key)
{
	int64_t val64, newval64;

	json_get_int64(&val64, sval, key);
	val64 += json_get_int64(&newval64, val, key);
	yyjson_mut_obj_put(sval, yyjson_mut_strcpy(doc, key), yyjson_mut_int(doc, val64));
}

static void set_maxdouble(yyjson_mut_doc *doc, yyjson_mut_val *sval, yyjson_mut_val *val, const char *key)
{
	double dval, newdval;

	json_get_double(&dval, sval, key);
	json_get_double(&newdval, val, key);
	if (newdval > dval)
		yyjson_mut_obj_put(sval, yyjson_mut_strcpy(doc, key), yyjson_mut_real(doc, newdval));
}

static void combine_stats(yyjson_mut_doc *doc, yyjson_mut_val *val, yyjson_mut_val *newval)
{
	add_hashrates(doc, val, newval, "hashrate1m");
	add_hashrates(doc, val, newval, "hashrate5m");
	add_hashrates(doc, val, newval, "hashrate1hr");
	add_hashrates(doc, val, newval, "hashrate1d");
	add_hashrates(doc, val, newval, "hashrate7d");
	set_maxint(doc, val, newval, "lastshare");
	add_int(doc, val, newval, "workers");
	add_int(doc, val, newval, "shares");
	set_maxdouble(doc, val, newval, "bestshare");
	set_maxint(doc, val, newval, "bestever");
	set_minint(doc, val, newval, "authorised");
}

user_t *get_user(const char *username, bool *new)
{
	user_t *user = NULL;

	HASH_FIND_STR(users, username, user);
	if (!user) {
		user = ckzalloc(sizeof(user_t));
		strncpy(user->username, username, 127);
		HASH_ADD_STR(users, username, user);
		*new = true;
	}
	return user;
}

static void init_worker_hash(user_t *user)
{
	yyjson_mut_val *warray = yyjson_mut_obj_get(user->json, "worker");
	worker_t *worker = NULL;
	yyjson_mut_val *w;
	size_t index, max;

	if (!warray || !yyjson_mut_is_arr(warray))
		return;

	yyjson_mut_arr_foreach(warray, index, max, w) {
		yyjson_mut_val *wn_val = yyjson_mut_obj_get(w, "workername");
		const char *workername = yyjson_mut_get_str(wn_val);
		if (!workername)
			continue;

		HASH_FIND_STR(user->workers, workername, worker);
		if (!worker) {
			worker = ckzalloc(sizeof(worker_t));
			strncpy(worker->workername, workername, 127);
			HASH_ADD_STR(user->workers, workername, worker);
			worker->json = w;   /* points to existing object inside the array */
		}
	}
}

void append_workers(user_t *user, yyjson_mut_val *sval)
{
	yyjson_mut_val *newvals = yyjson_mut_obj_get(sval, "worker");
	yyjson_mut_val *vals = yyjson_mut_obj_get(user->json, "worker");
	worker_t *worker = NULL;
	yyjson_mut_val *val;
	size_t index, max;

	if (!vals) {
		vals = yyjson_mut_arr(user->doc);
		yyjson_mut_obj_add_val(user->doc, user->json, "worker", vals);
	}
	if (!newvals || !yyjson_mut_is_arr(newvals))
		return;
	yyjson_mut_arr_foreach(newvals, index, max, val) {
		yyjson_mut_val *workername_val = yyjson_mut_obj_get(val, "workername");
		const char *workername = yyjson_mut_get_str(workername_val);

		if (!workername)
			continue;
		HASH_FIND_STR(user->workers, workername, worker);
		if (!worker) {
			/* Copy the worker into this user's document so it
			 * survives freeing of the source document. */
			yyjson_mut_val *copy = yyjson_mut_val_mut_copy(user->doc, val);

			worker = ckzalloc(sizeof(worker_t));
			strncpy(worker->workername, workername, 127);
			HASH_ADD_STR(user->workers, workername, worker);
			worker->json = copy;
			yyjson_mut_arr_add_val(vals, copy);
		} else
			combine_stats(user->doc, worker->json, val);
	}
}

bool parse_workers = false;

int main(int argc, char __maybe_unused **argv)
{
	double ghs1, ghs5, ghs15, ghs60, ghs360, ghs1440, ghs10080;
	char suffix1[16], suffix5[16], suffix15[16], suffix60[16];
	char suffix360[16], suffix1440[16], suffix10080[16];
	yyjson_mut_doc *confdoc, *doc;
	yyjson_mut_val *conf, *dirs, *val;
	size_t index, max;
	FILE *fp;
	char *s;
	int opt;

	while ((opt = getopt(argc, argv, "w")) != -1) {
		switch (opt) {
			case 'w':
				parse_workers = true;
			default:
				break;
		}
	}
	confdoc = read_json_file("ckpoolstats.conf");
	if (!confdoc)
		fail("Failed to load ckpoolstats.conf");
	conf = yyjson_mut_doc_get_root(confdoc);
	dirs = yyjson_mut_obj_get(conf, "dirs");
	if (!dirs || !yyjson_mut_is_arr(dirs))
		fail("dirs array not found");

	if (parse_workers)
		goto workers_only;

	umask(S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH);

	/* Read pool stats from each entry and create allstats */
	yyjson_mut_arr_foreach(dirs, index, max, val) {
		const char *dir = yyjson_mut_get_str(val);

		log("Found dir entry %s", dir);
		ASPRINTF(&s, "%s/pool/pool.status", dir);
		fp = fopen(s, "re");
		if (fp)
			log("Opened %s", s);
		else
			fail("Failed to open %s", s);
		read_poolstats(fp);
		fclose(fp);
		free(s);
	}

	/* Write pool.status for allstats */
	if (mkdir("pool", 0750) && errno != EEXIST)
		fail("Failed to create pool directory");
	fp = fopen("pool/pool.status", "we");
	if (!fp)
		fail("Failed to open updated pool.status file");
	doc = yyjson_mut_pack("{sI,sI,sI,sI,sI,sI}",
		   "runtime", allpstats.runtime,
	    "lastupdate", allpstats.lastupdate,
	    "Users", allpstats.users,
	    "Workers", allpstats.workers,
	    "Idle", allpstats.idle,
	    "Disconnected", allpstats.disconnected);

	s = yyjson_mut_write(doc, 0, NULL);
	fprintf(fp, "%s\n", s);
	log("Allstats pstats %s", s);
	free(s);
	yyjson_mut_doc_free(doc);

	ghs1 = alldsps.hashrate1m * nonces;
	suffix_string(ghs1, suffix1, 16, 0);

	ghs5 = alldsps.hashrate5m * nonces;
	suffix_string(ghs5, suffix5, 16, 0);

	ghs15 = alldsps.hashrate15m * nonces;
	suffix_string(ghs15, suffix15, 16, 0);

	ghs60 = alldsps.hashrate1hr * nonces;
	suffix_string(ghs60, suffix60, 16, 0);

	ghs360 = alldsps.hashrate6hr * nonces;
	suffix_string(ghs360, suffix360, 16, 0);

	ghs1440 = alldsps.hashrate1d * nonces;
	suffix_string(ghs1440, suffix1440, 16, 0);

	ghs10080 = alldsps.hashrate7d * nonces;
	suffix_string(ghs10080, suffix10080, 16, 0);

	doc = yyjson_mut_pack("{ss,ss,ss,ss,ss,ss,ss}",
			"hashrate1m", suffix1,
			"hashrate5m", suffix5,
			"hashrate15m", suffix15,
			"hashrate1hr", suffix60,
			"hashrate6hr", suffix360,
			"hashrate1d", suffix1440,
			"hashrate7d", suffix10080);

	s = yyjson_mut_write(doc, 0, NULL);
	fprintf(fp, "%s\n", s);
	log("Allstats dsps %s", s);
	free(s);
	yyjson_mut_doc_free(doc);

	doc = yyjson_mut_pack("{sf,sI,sI,sI,sf,sf,sf,sf}",
		   "diff", allsps.diff,
	    "accepted", allsps.accepted,
	    "rejected", allsps.rejected,
	    "bestshare", allsps.bestshare,
	    "SPS1m", allsps.sps1m,
	    "SPS5m", allsps.sps5m,
	    "SPS15m", allsps.sps15m,
	    "SPS1h", allsps.sps1h);
	/* Limit real precision to keep the status file tidy, as the jansson
	 * version did with JSON_REAL_PRECISION(6). */
	s = yyjson_mut_write(doc, YYJSON_WRITE_FP_TO_FIXED(6), NULL);
	fprintf(fp, "%s\n", s);
	fclose(fp);
	log("Allstats sps %s", s);
	free(s);
	yyjson_mut_doc_free(doc);
	goto out;

workers_only:
	yyjson_mut_arr_foreach(dirs, index, max, val) {
		struct dirent *dir;
		char *username;
		DIR *d;
		const char *sdir = yyjson_mut_get_str(val);

		ASPRINTF(&s, "%s/users", sdir);
		d = opendir(s);
		if (!d)
			fail("Failed to open users directory %s", s);
		free(s);

		while ((dir = readdir(d)) != NULL) {
			user_t *user = NULL;
			yyjson_mut_doc *fdoc;
			yyjson_mut_val *fval;
			bool new = false;

			username = basename(dir->d_name);
			if (!strcmp(username, "/") || !strcmp(username, ".") || !strcmp(username, ".."))
				continue;

			ASPRINTF(&s, "%s/users/%s", sdir, username);
			fdoc = read_json_file(s);
			free(s);
			if (!fdoc) /* Invalid or not user file */
				continue;
			fval = yyjson_mut_doc_get_root(fdoc);
			user = get_user(username, &new);
			if (new) {
				user->doc = fdoc;
				user->json = fval;
				init_worker_hash(user);
			} else {
				combine_stats(user->doc, user->json, fval);
				append_workers(user, fval);
				yyjson_mut_doc_free(fdoc);
			}
		}
		closedir(d);
	}

	user_t *user;

	if (mkdir("users", 0750) && errno != EEXIST)
		fail("Failed to create users directory");

	for (user = users; user != NULL; user = user->hh.next) {
		ASPRINTF(&s, "users/%s", user->username);
		if (!yyjson_mut_write_file(s, user->doc, YYJSON_WRITE_PRETTY_TWO_SPACES, NULL, NULL))
			fail("Failed to write user %s", user->username);
		free(s);
	}
out:
	yyjson_mut_doc_free(confdoc);

	return 0;
}
