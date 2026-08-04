/*
 * Copyright 2026 Con Kolivas
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 3 of the License, or (at your option)
 * any later version.  See COPYING for more details.
 */
#include <stdlib.h>
#include <stdio.h>
#include <sys/stat.h>
#include <dirent.h>
#include <math.h>
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

/* Our own persistent state, stored separately from the pool.status we
 * generate since the accepted/rejected counts we accumulate no longer match
 * the sum of the pools we read from once any of them has solved a block. */
#define STATE_VERSION 1

/* An accepted count dropping to less than this fraction of its previous value
 * is treated as a counter reset from a solved block rather than a pool that
 * has simply gone backwards. */
#define RESET_DIVISOR 10

/* Time in seconds since a worker's last share after which the stratifier
 * stops decaying its stats and drops it from the user file. Workers older
 * than this have frozen stats so we discard them as well. */
#define WORKER_EXPIRY 600000

typedef struct {
	UT_hash_handle hh;

	char *dir;
	/* Values stored by the last run */
	int64_t accepted;
	int64_t rejected;
	int64_t lastupdate;
	/* Values read this run */
	int64_t curaccepted;
	int64_t currejected;
	int64_t curlastupdate;
	double curdiff;
	bool known;	/* Was in the state file */
	bool present;	/* Is in the current config */
} pool_t;

pool_t *pools;

const char *statefile = "ckpoolstats.state";
int64_t total_accepted, total_rejected;
double networkdiff;
bool firstrun = true;

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

pool_t *get_pool(const char *dir)
{
	pool_t *pool = NULL;

	HASH_FIND_STR(pools, dir, pool);
	if (!pool) {
		pool = ckzalloc(sizeof(pool_t));
		pool->dir = strdup(dir);
		HASH_ADD_KEYPTR(hh, pools, pool->dir, strlen(pool->dir), pool);
	}
	return pool;
}

/* Read our own accumulated state from the last run, if any. Leaves firstrun
 * set if there is no usable state file, in which case we simply summate all
 * the configs we load. */
static void read_state(void)
{
	yyjson_mut_val *root, *parr, *pval;
	int64_t version = 0;
	yyjson_mut_doc *doc;
	size_t index, max;

	doc = read_json_file(statefile);
	if (!doc) {
		log("No state file %s found, summating all configs", statefile);
		return;
	}
	root = yyjson_mut_doc_get_root(doc);
	json_get_int64(&version, root, "version");
	if (version != STATE_VERSION) {
		logerr("State file %s is version %"PRId64" instead of %d, discarding",
		       statefile, version, STATE_VERSION);
		goto out;
	}
	firstrun = false;
	json_get_int64(&total_accepted, root, "accepted");
	json_get_int64(&total_rejected, root, "rejected");
	json_get_double(&networkdiff, root, "networkdiff");
	log("Loaded state accepted %"PRId64" rejected %"PRId64" networkdiff %.1f",
	    total_accepted, total_rejected, networkdiff);

	parr = yyjson_mut_obj_get(root, "pools");
	if (!parr || !yyjson_mut_is_arr(parr)) {
		/* Without the per pool baselines we would add every pool's
		 * entire count to the totals so start over instead. */
		logerr("No pools array found in state file %s, discarding", statefile);
		total_accepted = total_rejected = 0;
		firstrun = true;
		goto out;
	}
	yyjson_mut_arr_foreach(parr, index, max, pval) {
		yyjson_mut_val *dval = yyjson_mut_obj_get(pval, "dir");
		const char *dir = yyjson_mut_get_str(dval);
		pool_t *pool;

		if (!dir) {
			logerr("No dir entry found in state file pool entry");
			continue;
		}
		pool = get_pool(dir);
		pool->known = true;
		json_get_int64(&pool->accepted, pval, "accepted");
		json_get_int64(&pool->rejected, pval, "rejected");
		json_get_int64(&pool->lastupdate, pval, "lastupdate");
		log("Loaded state for pool %s accepted %"PRId64" rejected %"PRId64,
		    pool->dir, pool->accepted, pool->rejected);
	}
out:
	yyjson_mut_doc_free(doc);
}

/* Write the state out via a temporary file and rename so an interrupted run
 * can never leave a truncated state behind. */
static void write_state(void)
{
	yyjson_mut_val *root, *parr;
	yyjson_mut_doc *doc;
	pool_t *pool, *tmp;
	char *tmpfile;
	tv_t now;

	tv_time(&now);
	doc = yyjson_mut_pack("{si,sI,sI,sI,sf}",
		     "version", STATE_VERSION,
		  "lastupdate", (int64_t)now.tv_sec,
		    "accepted", total_accepted,
		    "rejected", total_rejected,
		 "networkdiff", networkdiff);
	if (unlikely(!doc))
		fail("Failed to create state document");
	root = yyjson_mut_doc_get_root(doc);
	parr = yyjson_mut_arr(doc);
	yyjson_mut_obj_add_val(doc, root, "pools", parr);

	HASH_ITER(hh, pools, pool, tmp) {
		yyjson_mut_val *pval;

		/* Drop any pool no longer in the config from the state */
		if (!pool->present)
			continue;
		pval = yyjson_mut_pack_val(doc, "{ss,sI,sI,sI}",
			       "dir", pool->dir,
			  "accepted", pool->accepted,
			  "rejected", pool->rejected,
			"lastupdate", pool->lastupdate);
		if (unlikely(!pval))
			fail("Failed to create state entry for pool %s", pool->dir);
		yyjson_mut_arr_add_val(parr, pval);
	}

	ASPRINTF(&tmpfile, "%s.tmp", statefile);
	if (!yyjson_mut_write_file(tmpfile, doc, YYJSON_WRITE_PRETTY_TWO_SPACES, NULL, NULL))
		fail("Failed to write state file %s", tmpfile);
	if (rename(tmpfile, statefile))
		fail("Failed to rename %s to %s", tmpfile, statefile);
	log("Wrote state file %s accepted %"PRId64" rejected %"PRId64,
	    statefile, total_accepted, total_rejected);
	free(tmpfile);
	yyjson_mut_doc_free(doc);
}

/* A pool zeroes its accepted and rejected counts when it solves a block so a
 * drop to zero, or close enough to it, tells us a block was found. */
static bool solved_block(const pool_t *pool)
{
	return (pool->curaccepted < pool->accepted &&
		pool->curaccepted * RESET_DIVISOR < pool->accepted);
}

/* Accumulate our own running totals from the difference in each pool's counts
 * since the last run, resetting the totals if any pool solved a block. */
static void update_totals(void)
{
	int64_t deltaacc = 0, deltarej = 0, prevacc = 0, prevrej = 0;
	bool blocksolved = false;
	pool_t *pool, *tmp;

	HASH_ITER(hh, pools, pool, tmp) {
		int64_t dacc, drej;

		if (!pool->present)
			continue;
		if (!pool->known) {
			/* A config we've not seen before contributes all of
			 * its counts and is tracked from here on. */
			if (!firstrun) {
				log("New pool %s adding accepted %"PRId64" rejected %"PRId64,
				    pool->dir, pool->curaccepted, pool->currejected);
			}
			deltaacc += pool->curaccepted;
			deltarej += pool->currejected;
			continue;
		}
		prevacc += pool->accepted;
		prevrej += pool->rejected;
		if (solved_block(pool)) {
			log("Pool %s accepted dropped from %"PRId64" to %"PRId64", block solved",
			    pool->dir, pool->accepted, pool->curaccepted);
			blocksolved = true;
			/* Everything it has now is since the block */
			dacc = pool->curaccepted;
			drej = pool->currejected;
		} else {
			dacc = pool->curaccepted - pool->accepted;
			drej = pool->currejected - pool->rejected;
			/* Counts should never go backwards otherwise but
			 * never subtract from our totals if they do. */
			if (dacc < 0)
				dacc = 0;
			if (drej < 0)
				drej = 0;
		}
		deltaacc += dacc;
		deltarej += drej;
	}

	if (blocksolved) {
		/* Discard everything accounted for by the solved block and
		 * start a new baseline from this run's differences alone. */
		total_accepted -= prevacc;
		total_rejected -= prevrej;
		if (total_accepted < 0)
			total_accepted = 0;
		if (total_rejected < 0)
			total_rejected = 0;
	}
	total_accepted += deltaacc;
	total_rejected += deltarej;

	/* Store this run's counts as the baseline for the next run */
	HASH_ITER(hh, pools, pool, tmp) {
		if (!pool->present)
			continue;
		pool->accepted = pool->curaccepted;
		pool->rejected = pool->currejected;
		pool->lastupdate = pool->curlastupdate;
	}

	allsps.accepted = total_accepted;
	allsps.rejected = total_rejected;
}

/* Each pool stores the proportion of the network difficulty it has found as a
 * percentage so we can recover the network difficulty it is working on from
 * its own accepted count, using the pool with the largest percentage for the
 * best precision, and keeping the last known value if none can be derived. */
static void update_networkdiff(void)
{
	double bestpct = 0, ndiff = 0;
	pool_t *pool, *tmp;

	HASH_ITER(hh, pools, pool, tmp) {
		if (!pool->present || pool->curdiff <= 0 || pool->curaccepted < 1)
			continue;
		if (pool->curdiff > bestpct) {
			bestpct = pool->curdiff;
			ndiff = (double)pool->curaccepted * 100 / pool->curdiff;
		}
	}
	if (ndiff > 0)
		networkdiff = ndiff;
	if (networkdiff > 0) {
		/* Round to 4 significant digits as the pools do */
		allsps.diff = round(total_accepted * 10000 / networkdiff) / 100;
	} else
		logerr("Unable to determine network difficulty from any pool");
}

void read_poolstats(pool_t *pool, FILE *fp)
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
	pool->curlastupdate = json_get_int64(&poolpstats.lastupdate, val, "lastupdate");
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
	/* The pool's diff is the percentage of the network difficulty it has
	 * found which we recalculate from our own accepted count. */
	pool->curdiff = json_get_double(&poolsps.diff, val , "diff");
	allsps.sps1m += json_get_double(&poolsps.sps1m, val, "SPS1m");
	allsps.sps5m += json_get_double(&poolsps.sps5m, val, "SPS5m");
	allsps.sps15m += json_get_double(&poolsps.sps15m, val, "SPS15m");
	allsps.sps1h += json_get_double(&poolsps.sps1h, val, "SPS1h");
	/* Accepted and rejected are accumulated in our own state instead of
	 * being summated as the pools reset them on solving a block. */
	pool->curaccepted = json_get_int64(&poolsps.accepted, val, "accepted");
	pool->currejected = json_get_int64(&poolsps.rejected, val, "rejected");
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

static const char *hashrate_keys[] = {
	"hashrate1m", "hashrate5m", "hashrate1hr", "hashrate1d", "hashrate7d", NULL
};

static void combine_hashrates(yyjson_mut_doc *doc, yyjson_mut_val *val, yyjson_mut_val *newval)
{
	int i;

	for (i = 0; hashrate_keys[i]; i++)
		add_hashrates(doc, val, newval, hashrate_keys[i]);
}

/* Hashrates are handled separately since a user's are accumulated from only
 * those of its workers we keep. */
static void combine_stats(yyjson_mut_doc *doc, yyjson_mut_val *val, yyjson_mut_val *newval)
{
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

/* Current time, sampled once at startup as the reference for expiry. */
static int64_t now_t;

/* Workers whose last share is older than WORKER_EXPIRY have had their stats
 * frozen by the stratifier so must not be collated. */
static bool worker_expired(yyjson_mut_val *wval)
{
	int64_t lastshare;

	/* Without a lastshare we have no way of telling, so keep it */
	if (!yyjson_mut_obj_get(wval, "lastshare"))
		return false;
	json_get_int64(&lastshare, wval, "lastshare");
	return (now_t - lastshare > WORKER_EXPIRY);
}

/* Discard the hashrates from the source file, which include those of the
 * workers we're dropping, ready to be accumulated from the workers we keep. */
static void zero_hashrates(user_t *user)
{
	int i;

	for (i = 0; hashrate_keys[i]; i++) {
		yyjson_mut_obj_put(user->json, yyjson_mut_strcpy(user->doc, hashrate_keys[i]),
				   yyjson_mut_strcpy(user->doc, "0"));
	}
}

static void init_worker_hash(user_t *user)
{
	yyjson_mut_val *warray = yyjson_mut_obj_get(user->json, "worker");
	worker_t *worker = NULL;
	yyjson_mut_val *w;
	size_t index = 0;

	if (!warray || !yyjson_mut_is_arr(warray))
		return;

	zero_hashrates(user);

	while (index < yyjson_mut_arr_size(warray)) {
		yyjson_mut_val *wn_val;
		const char *workername;

		w = yyjson_mut_arr_get(warray, index);
		if (worker_expired(w)) {
			yyjson_mut_arr_remove(warray, index);
			continue;
		}
		combine_hashrates(user->doc, user->json, w);
		wn_val = yyjson_mut_obj_get(w, "workername");
		workername = yyjson_mut_get_str(wn_val);
		if (!workername) {
			index++;
			continue;
		}

		HASH_FIND_STR(user->workers, workername, worker);
		if (!worker) {
			worker = ckzalloc(sizeof(worker_t));
			strncpy(worker->workername, workername, 127);
			HASH_ADD_STR(user->workers, workername, worker);
			worker->json = w;   /* points to existing object inside the array */
		}
		index++;
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
		if (worker_expired(val)) {
			LOGDEBUG("Skipping inactive worker %s", workername);
			continue;
		}
		combine_hashrates(user->doc, user->json, val);
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
		} else {
			combine_hashrates(user->doc, worker->json, val);
			combine_stats(user->doc, worker->json, val);
		}
	}
}

bool parse_workers = false;

int main(int argc, char __maybe_unused **argv)
{
	double ghs1, ghs5, ghs15, ghs60, ghs360, ghs1440, ghs10080;
	char suffix1[16], suffix5[16], suffix15[16], suffix60[16];
	char suffix360[16], suffix1440[16], suffix10080[16];
	yyjson_mut_doc *confdoc, *doc;
	yyjson_mut_val *conf, *dirs, *val, *sval;
	size_t index, max;
	FILE *fp;
	char *s;
	int opt;

	now_t = time(NULL);

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

	/* umask takes the permission bits to remove so mask off only write
	 * for other, creating our files 0664. */
	umask(S_IWOTH);

	sval = yyjson_mut_obj_get(conf, "statefile");
	if (sval && yyjson_mut_is_str(sval))
		statefile = yyjson_mut_get_str(sval);

	/* Load our own accumulated stats from the last run, if any */
	read_state();

	/* Read pool stats from each entry and create allstats */
	yyjson_mut_arr_foreach(dirs, index, max, val) {
		const char *dir = yyjson_mut_get_str(val);
		pool_t *pool;

		log("Found dir entry %s", dir);
		pool = get_pool(dir);
		pool->present = true;
		ASPRINTF(&s, "%s/pool/pool.status", dir);
		fp = fopen(s, "re");
		if (fp)
			log("Opened %s", s);
		else
			fail("Failed to open %s", s);
		read_poolstats(pool, fp);
		fclose(fp);
		free(s);
	}

	/* Accumulate our own accepted/rejected totals and derive the network
	 * difficulty percentage from them before writing anything out. */
	update_totals();
	update_networkdiff();
	write_state();

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
