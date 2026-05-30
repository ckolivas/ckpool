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

void read_poolstats(FILE *fp)
{
	char *s = alloca(4096), *pstats, *dsps, *sps;
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
	json_decref(val);

	val = json_loads(dsps, 0, NULL);
	if (!val)
		fail("Failed to json decode dsps line from pool logfile: %s", sps);
	json_decref(val);

	val = json_loads(sps, 0, NULL);
	if (!val)
		fail("Failed to json decode sps line from pool logfile: %s", dsps);
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
