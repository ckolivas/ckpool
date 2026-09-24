/*
 * Copyright 2026 Con Kolivas
 *
 * Reproduce huge rejected-difficulty batches and totals without a live miner,
 * and exercise the stratifier's accounting before and after a client's first
 * accepted share.
 */
#include "config.h"
#include <assert.h>
#include <math.h>
#include <stdio.h>

#include "../src/stratifier.c"

static void test_client_rejects(void)
{
	stratum_instance_t client = {0}, other = {0}, highdiff = {0}, sv2 = {0};
	pool_stats_t stats = {0};
	int i;

	client.start_diff = 1024;
	client.diff = client.suggest_diff = 1000000000000000000LL;
	for (i = 0; i < 20; i++)
		account_client_share(&stats, &client, client.diff, false);
	assert(stats.unaccounted_rejects == 20 * 1024);
	assert(!client.has_accepted_share);
	assert(!stats.unaccounted_shares && !stats.unaccounted_diff_shares);

	/* A timestamp set by stale work must not unlock suggested difficulty. */
	client.first_share.tv_sec = 1;
	account_client_share(&stats, &client, client.diff, false);
	assert(stats.unaccounted_rejects == 21 * 1024);
	assert(!client.has_accepted_share);

	/* Only acceptance changes the policy; credit the actual accepted diff. */
	account_client_share(&stats, &client, 4096, true);
	assert(client.has_accepted_share);
	assert(stats.unaccounted_shares == 1 && stats.unaccounted_diff_shares == 4096);
	account_client_share(&stats, &client, 8192, false);
	assert(stats.unaccounted_rejects == 21 * 1024 + 8192);

	/* Pool stats resets must not erase this connection's accepted history. */
	memset(&stats, 0, sizeof(stats));
	account_client_share(&stats, &client, 16384, false);
	assert(stats.unaccounted_rejects == 16384);

	/* Another connection, even for the same worker, starts unproven. */
	other.start_diff = 1024;
	other.worker_instance = client.worker_instance;
	account_client_share(&stats, &other, 1e18, false);
	assert(stats.unaccounted_rejects == 16384 + 1024);
	assert(!other.has_accepted_share);

	/* Preserve each port's initial difficulty, not just global startdiff. */
	highdiff.start_diff = 1000000;
	account_client_share(&stats, &highdiff, 1e18, false);
	assert(stats.unaccounted_rejects == 16384 + 1024 + 1000000);

	/* SV2 negotiated difficulty cannot inflate rejects before acceptance. */
	sv2.start_diff = 1024;
	sv2.sv2 = true;
	sv2.diff = 1000000000000000LL;
	stats.unaccounted_rejects = 0;
	account_client_share(&stats, &sv2, sv2.diff, false);
	assert(stats.unaccounted_rejects == 1024);

	/* Established clients remain unable to overflow the reject accumulator. */
	for (i = 0; i < 20; i++)
		account_client_share(&stats, &client, 1e18, false);
	assert(stats.unaccounted_rejects == INT64_MAX);
}

int main(void)
{
	int64_t pending = 0, total = 0;
	int i;

	test_client_rejects();
	assert(add_reject_diff(100, 42) == 142);
	assert(add_reject_diff(100, 42.5) == 142);
	assert(add_reject_diff(100, 0) == 100);
	assert(add_reject_diff(100, -1) == 100);
	assert(add_reject_diff(100, NAN) == 100);
	assert(add_reject_diff(100, INFINITY) == INT64_MAX);
	assert(add_reject_diff(0, 0x1p63) == INT64_MAX);
	assert(add_reject_diff(0, nextafter(0x1p63, 0)) == INT64_MAX - 1023);
	assert(add_reject_diff(INT64_MAX, 1) == INT64_MAX);
	assert(add_reject_diff(INT64_MAX - 1, 1) == INT64_MAX);
	assert(add_reject_diff(INT64_MAX - 1, 2) == INT64_MAX);
	assert(add_rejects(INT64_MAX - 1, 0) == INT64_MAX - 1);
	assert(add_rejects(0, INT64_MAX) == INT64_MAX);
	assert(add_rejects(INT64_MAX, INT64_MAX) == INT64_MAX);
	assert(add_rejects(0, -1) == 0);
	assert(add_rejects(INT64_MIN, 42) == 42);

	/* Many rejections within one stats interval. */
	for (i = 0; i < 20; i++)
		pending = add_reject_diff(pending, 1e18);
	assert(pending == INT64_MAX);

	/* The same submissions spread across stats intervals. */
	for (i = 0; i < 20; i++) {
		pending = add_reject_diff(0, 1e18);
		total = add_rejects(total, pending);
	}
	assert(total == INT64_MAX);
	assert(add_rejects(total, 0) == INT64_MAX);

	/* A block reset starts a fresh counter. */
	total = 0;
	assert(add_rejects(total, 42) == 42);
	puts("reject_stats: all OK");
	return 0;
}
