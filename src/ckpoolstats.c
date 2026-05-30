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

int main(int __maybe_unused argc, char __maybe_unused **argv)
{
	json_t *conf, *dirs, *val;
	size_t index;

	conf = json_load_file("ckpoolstats.conf", 0, NULL);
	if (!conf)
		fail("Failed to load ckpoolstats.conf");
	dirs = json_object_get(conf, "dirs");
	if (!dirs || !json_is_array(dirs))
		fail("dirs array not found");

	json_array_foreach(dirs, index, val) {
		const char *dir = json_string_value(val);
		log("Found dir %s", dir);
	}

	json_decref(conf);

	return 0;
}
