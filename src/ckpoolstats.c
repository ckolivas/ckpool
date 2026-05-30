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
	json_t *json;
} worker_t;

typedef struct {
	UT_hash_handle hh;

	char username[128];
	json_t *json;
	worker_t *workers;
} user_t;

user_t *users;

int64_t json_get_int64(int64_t *store, const json_t *val, const char *res)
{
	json_t *entry = json_object_get(val, res);
	*store = 0;

	if (!entry) {
		LOGDEBUG("Json did not find entry %s", res);
		goto out;
	}
	if (!json_is_integer(entry)) {
		LOGINFO("Json entry %s is not an integer", res);
		goto out;
	}
	*store = json_integer_value(entry);
	LOGDEBUG("Json found entry %s: %"PRId64, res, *store);
out:
	return *store;
}

double json_get_double(double *store, const json_t *val, const char *res)
{
	json_t *entry = json_object_get(val, res);
	*store = 0;

	if (!entry) {
		LOGDEBUG("Json did not find entry %s", res);
		goto out;
	}
	if (!json_is_real(entry)) {
		LOGWARNING("Json entry %s is not a double", res);
		goto out;
	}
	*store = json_real_value(entry);
	LOGDEBUG("Json found entry %s: %f", res, *store);
out:
	return *store;
}

const double nonces = 4294967296;

bool json_get_string(char **store, const json_t *entry, const char *res)
{
	bool ret = false;
	const char *buf;

	*store = NULL;
	if (!entry || json_is_null(entry)) {
		LOGDEBUG("Json did not find entry %s", res);
		goto out;
	}
	if (!json_is_string(entry)) {
		LOGWARNING("Json entry %s is not a string", res);
		goto out;
	}
	buf = json_string_value(entry);
	LOGDEBUG("Json found entry %s: %s", res, buf);
	*store = strdup(buf);
	ret = true;
out:
	return ret;
}

/* Fallthrough intentional */
double dsps_from_key(json_t *sval, const char *key)
{
	char *string, *endptr;
	double ret = 0;
	json_t *val;

	val = json_object_get(sval, key);
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
	json_t *val;
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
	val = json_loads(pstats, 0, NULL);
	if (!val)
		fail("Failed to json decode pstats line from pool logfile: %s", pstats);
	json_get_int64(&poolpstats.runtime, val, "runtime");
	json_get_int64(&poolpstats.lastupdate, val, "lastupdate");
	allpstats.users += json_get_int64(&poolpstats.users, val, "Users");
	allpstats.workers += json_get_int64(&poolpstats.workers, val, "Workers");
	allpstats.idle += json_get_int64(&poolpstats.idle, val, "Idle");
	allpstats.disconnected += json_get_int64(&poolpstats.disconnected, val, "Disconnected");
	json_decref(val);

	/* Pessimise these two values from worst stats */
	if (!allpstats.runtime || allpstats.runtime > poolpstats.runtime)
		allpstats.runtime = poolpstats.runtime;
	if (!allpstats.lastupdate || allpstats.lastupdate > poolpstats.lastupdate)
		allpstats.lastupdate = poolpstats.lastupdate;

	val = json_loads(dsps, 0, NULL);
	if (!val)
		fail("Failed to json decode dsps line from pool logfile: %s", sps);
	alldsps.hashrate1m += dsps_from_key(val, "hashrate1m");
	alldsps.hashrate5m += dsps_from_key(val, "hashrate5m");
	alldsps.hashrate15m += dsps_from_key(val, "hashrate15m");
	alldsps.hashrate1hr += dsps_from_key(val, "hashrate1hr");
	alldsps.hashrate6hr += dsps_from_key(val, "hashrate6hr");
	alldsps.hashrate1d += dsps_from_key(val, "hashrate1d");
	alldsps.hashrate7d += dsps_from_key(val, "hashrate7d");
	json_decref(val);

	val = json_loads(sps, 0, NULL);
	if (!val)
		fail("Failed to json decode sps line from pool logfile: %s", dsps);
	allsps.diff += json_get_double(&poolsps.diff, val , "diff");
	allsps.sps1m += json_get_double(&poolsps.sps1m, val, "SPS1m");
	allsps.sps5m += json_get_double(&poolsps.sps5m, val, "SPS5m");
	allsps.sps15m += json_get_double(&poolsps.sps15m, val, "SPS15m");
	allsps.sps1h += json_get_double(&poolsps.sps1h, val, "SPS1h");
	allsps.accepted += json_get_int64(&poolsps.accepted, val, "accepted");
	allsps.rejected += json_get_int64(&poolsps.rejected, val, "rejected");
	json_get_int64(&poolsps.bestshare, val, "bestshare");
	if (poolsps.bestshare > allsps.bestshare)
		allsps.bestshare = poolsps.bestshare;
	json_decref(val);
}

static void add_hashrates(json_t *sval, json_t *val, const char *key)
{
	double ghs, dval = dsps_from_key(sval, key);
	char suffix[16];

	dval += dsps_from_key(val, key);
	ghs = dval * nonces;
	suffix_string(ghs, suffix, 16, 0);
	json_object_set_new(sval, key, json_string(suffix));
}

static void set_maxint(json_t *sval, json_t *val, const char *key)
{
	int64_t val64, newval64;

	json_get_int64(&val64, sval, key);
	json_get_int64(&newval64, val, key);
	if (newval64 > val64)
		json_object_set_new(sval, key, json_integer(newval64));
}

static void set_minint(json_t *sval, json_t *val, const char *key)
{
	int64_t val64, newval64;

	json_get_int64(&val64, sval, key);
	json_get_int64(&newval64, val, key);
	if (newval64 < val64)
		json_object_set_new(sval, key, json_integer(newval64));
}

static void add_int(json_t *sval, json_t *val, const char *key)
{
	int64_t val64, newval64;

	json_get_int64(&val64, sval, key);
	val64 += json_get_int64(&newval64, val, key);
	json_object_set_new(sval, key, json_integer(val64));
}

static void set_maxdouble(json_t *sval, json_t *val, const char *key)
{
	double dval, newdval;

	json_get_double(&dval, sval, key);
	json_get_double(&newdval, val, key);
	if (newdval > dval)
		json_object_set_new(sval, key, json_real(newdval));
}

static void combine_stats(json_t *val, json_t *newval)
{
	add_hashrates(val, newval, "hashrate1m");
	add_hashrates(val, newval, "hashrate5m");
	add_hashrates(val, newval, "hashrate1hr");
	add_hashrates(val, newval, "hashrate1d");
	add_hashrates(val, newval, "hashrate7d");
	set_maxint(val, newval, "lastshare");
	add_int(val, newval, "workers");
	add_int(val, newval, "shares");
	set_maxdouble(val, newval, "bestshare");
	set_maxint(val, newval, "bestever");
	set_minint(val, newval, "authorised");
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
	json_t *warray = json_object_get(user->json, "worker");
	json_t *w;
	size_t index;
	worker_t *worker = NULL;

	if (!warray || !json_is_array(warray))
		return;

	json_array_foreach(warray, index, w) {
		json_t *wn_val = json_object_get(w, "workername");
		const char *workername = json_string_value(wn_val);
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

void append_workers(user_t *user, json_t *sval)
{
	json_t *newvals = json_object_get(sval, "worker");
	json_t *vals = json_object_get(user->json, "worker");
	worker_t *worker = NULL;
	json_t *val;
	size_t index;

	if (!vals) {
		json_object_set(user->json, "worker", json_array());
		vals = json_object_get(user->json, "worker");
	}
	if (!newvals || !json_is_array(newvals))
		return;
	json_array_foreach(newvals, index, val) {
		json_t *workername_val = json_object_get(val, "workername");
		const char *workername = json_string_value(workername_val);

		HASH_FIND_STR(user->workers, workername, worker);
		if (!worker) {
			worker = ckzalloc(sizeof(worker_t));
			strncpy(worker->workername, workername, 127);
			HASH_ADD_STR(user->workers, workername, worker);
			worker->json = val;
			json_array_append(vals, val);
		} else
			combine_stats(worker->json, val);
	}
}

bool parse_workers = false;

int main(int argc, char __maybe_unused **argv)
{
	double ghs1, ghs5, ghs15, ghs60, ghs360, ghs1440, ghs10080;
	char suffix1[16], suffix5[16], suffix15[16], suffix60[16];
	char suffix360[16], suffix1440[16], suffix10080[16];
	json_t *conf, *dirs, *val;
	size_t index;
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
	conf = json_load_file("ckpoolstats.conf", 0, NULL);
	if (!conf)
		fail("Failed to load ckpoolstats.conf");
	dirs = json_object_get(conf, "dirs");
	if (!dirs || !json_is_array(dirs))
		fail("dirs array not found");

	if (parse_workers)
		goto workers_only;

	/* Read pool stats from each entry and create allstats */
	json_array_foreach(dirs, index, val) {
		const char *dir = json_string_value(val);

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
	JSON_CPACK(val, "{si,si,si,si,si,si}",
		   "runtime", allpstats.runtime,
	    "lastupdate", allpstats.lastupdate,
	    "Users", allpstats.users,
	    "Workers", allpstats.workers,
	    "Idle", allpstats.idle,
	    "Disconnected", allpstats.disconnected);

	s = json_dumps(val, JSON_NO_UTF8 | JSON_PRESERVE_ORDER);
	fprintf(fp, "%s\n", s);
	log("Allstats pstats %s", s);
	free(s);
	json_decref(val);

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

	JSON_CPACK(val, "{ss,ss,ss,ss,ss,ss,ss}",
			"hashrate1m", suffix1,
			"hashrate5m", suffix5,
			"hashrate15m", suffix15,
			"hashrate1hr", suffix60,
			"hashrate6hr", suffix360,
			"hashrate1d", suffix1440,
			"hashrate7d", suffix10080);

	s = json_dumps(val, JSON_NO_UTF8 | JSON_PRESERVE_ORDER);
	fprintf(fp, "%s\n", s);
	log("Allstats dsps %s", s);
	free(s);
	json_decref(val);

	JSON_CPACK(val,"{sf,sI,sI,sI,sf,sf,sf,sf}",
		   "diff", allsps.diff,
	    "accepted", allsps.accepted,
	    "rejected", allsps.rejected,
	    "bestshare", allsps.bestshare,
	    "SPS1m", allsps.sps1m,
	    "SPS5m", allsps.sps5m,
	    "SPS15m", allsps.sps15m,
	    "SPS1h", allsps.sps1h);
	s = json_dumps(val, JSON_NO_UTF8 | JSON_PRESERVE_ORDER | JSON_REAL_PRECISION(6));
	fprintf(fp, "%s\n", s);
	fclose(fp);
	log("Allstats sps %s", s);
	free(s);
	json_decref(val);
	goto out;

workers_only:
	json_array_foreach(dirs, index, val) {
		struct dirent *dir;
		char *username;
		DIR *d;
		const char *sdir = json_string_value(val);

		ASPRINTF(&s, "%s/users", sdir);
		d = opendir(s);
		if (!d)
			fail("Failed to open users directory %s", s);
		free(s);

		while ((dir = readdir(d)) != NULL) {
			user_t *user = NULL;
			bool new = false;

			username = basename(dir->d_name);
			if (!strcmp(username, "/") || !strcmp(username, ".") || !strcmp(username, ".."))
				continue;

			ASPRINTF(&s, "%s/users/%s", sdir, username);
			fp = fopen(s, "re");
			if (!fp) {
				log("Failed to open user %s", username);
				continue;
			}
			val = json_load_file(s, 0, NULL);
			if (!val) /* Invalid or not user file */
				continue;
			free(s);
			user = get_user(username, &new);
			if (new) {
				user->json = val;
				init_worker_hash(user);
			} else {
				combine_stats(user->json, val);
				append_workers(user, val);
				json_decref(val);
			}
			fclose(fp);
		}
		closedir(d);
	}

	user_t *user;

	if (mkdir("users", 0750) && errno != EEXIST)
		fail("Failed to create users directory");

	for (user = users; user != NULL; user = user->hh.next) {
		ASPRINTF(&s, "users/%s", user->username);
		fp = fopen(s, "we");
		free(s);
		if (!fp)
			fail("Failed to write user %s", user->username);
		json_dumpf(user->json, fp, JSON_INDENT(2));
		fclose(fp);
	}
out:
	json_decref(conf);

	return 0;
}
