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

#include "libckpool.h"

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
	int64_t accepted;
	int64_t rejected;
	int64_t bestshare;
} sps_t;

/* Global combined stats */
pstats_t allpstats;
dsps_t alldsps;
sps_t allsps;

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
double dsps_from_key(json_t *val, const char *key)
{
	char *string, *endptr;
	double ret = 0;

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
	allsps.sps1m += json_get_double(&poolsps.sps1m, val, "sps1m");
	allsps.sps5m += json_get_double(&poolsps.sps5m, val, "sps5m");
	allsps.sps15m += json_get_double(&poolsps.sps15m, val, "sps15m");
	allsps.accepted += json_get_int64(&poolsps.accepted, val, "accepted");
	allsps.rejected += json_get_int64(&poolsps.rejected, val, "rejected");
	json_get_int64(&poolsps.bestshare, val, "bestshare");
	if (poolsps.bestshare > allsps.bestshare)
		allsps.bestshare = poolsps.bestshare;
	json_decref(val);
}

int main(int __maybe_unused argc, char __maybe_unused **argv)
{
	json_t *conf, *dirs, *val;
	size_t index;
	FILE *fp;
	char *s;

	conf = json_load_file("ckpoolstats.conf", 0, NULL);
	if (!conf)
		fail("Failed to load ckpoolstats.conf");
	dirs = json_object_get(conf, "dirs");
	if (!dirs || !json_is_array(dirs))
		fail("dirs array not found");

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

	json_decref(conf);

	return 0;
}
