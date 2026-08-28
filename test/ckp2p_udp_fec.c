/*
 * Copyright 2026 Con Kolivas
 *
 * FEC round-trip tests for ckp2p UDP shards.
 */

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "libckpool.h"
#include "ckp2p_fec.h"

static int failures;

static void fail(const char *msg)
{
	fprintf(stderr, "FAIL: %s\n", msg);
	failures++;
}

static void test_roundtrip(uint32_t len, double drop_frac)
{
	uchar *src, *dst, *block, *base, **ptrs, **recv;
	unsigned idxs[P2P_FEC_MAX_N];
	int k, n, i, got, drop;
	char msg[128];

	k = p2p_fec_k_for_bytes(len);
	n = p2p_fec_n(k);
	src = ckzalloc(len ? len : 1);
	dst = ckzalloc(len ? len : 1);
	for (i = 0; i < (int)len; i++)
		src[i] = (uchar)(i * 31u + 7u);

	block = ckzalloc((size_t)n * P2P_FEC_SHARD + 64);
	base = (uchar *)(((uintptr_t)block + 31) & ~(uintptr_t)31);
	ptrs = ckalloc(sizeof(uchar *) * n);
	recv = ckalloc(sizeof(uchar *) * n);
	for (i = 0; i < n; i++)
		ptrs[i] = base + (size_t)i * P2P_FEC_SHARD;

	if (!p2p_fec_encode(src, len, k, n, ptrs)) {
		snprintf(msg, sizeof(msg), "encode len=%u k=%d n=%d", len, k, n);
		fail(msg);
		goto out;
	}

	got = 0;
	for (i = 0; i < n; i++) {
		drop = 0;
		if (drop_frac > 0 && n > k) {
			/* Keep at least k shards; drop from the tail first. */
			if (i >= k && (double)rand() / RAND_MAX < drop_frac)
				drop = 1;
		}
		if (!drop) {
			recv[got] = ptrs[i];
			idxs[got] = (unsigned)i;
			got++;
		}
	}
	if (got < k) {
		/* Force enough shards if RNG dropped too many */
		got = 0;
		for (i = 0; i < k; i++) {
			recv[got] = ptrs[i];
			idxs[got] = (unsigned)i;
			got++;
		}
	}

	if (!p2p_fec_decode(recv, idxs, got, k, n, dst, len)) {
		snprintf(msg, sizeof(msg), "decode len=%u k=%d n=%d got=%d", len, k, n, got);
		fail(msg);
		goto out;
	}
	if (len && memcmp(src, dst, len)) {
		snprintf(msg, sizeof(msg), "mismatch len=%u k=%d n=%d", len, k, n);
		fail(msg);
	}
out:
	dealloc(src);
	dealloc(dst);
	dealloc(block);
	dealloc(ptrs);
	dealloc(recv);
}

static void test_size_cap(void)
{
	int k = p2p_fec_k_for_bytes(25000);
	int n = p2p_fec_n(k);
	int pkt = 44 + P2P_FEC_SHARD;

	if (pkt > 1400)
		fail("datagram exceeds 1400");
	if (k < 1 || n <= k)
		fail("bad k/n for 25k");
	if (p2p_fec_n(1) < 3)
		fail("k=1 should produce n>=3");
}

int main(void)
{
	srand(1);
	test_size_cap();
	test_roundtrip(0, 0);
	test_roundtrip(1, 0);
	test_roundtrip(P2P_FEC_SHARD - 1, 0.3);
	test_roundtrip(P2P_FEC_SHARD, 0.3);
	test_roundtrip(25000, 0.3);
	test_roundtrip(P2P_FEC_MAX_K * P2P_FEC_SHARD, 0.3);
	if (failures) {
		fprintf(stderr, "%d failures\n", failures);
		return 1;
	}
	printf("ckp2p_udp_fec: ok\n");
	return 0;
}
