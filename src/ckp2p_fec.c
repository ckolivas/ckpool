/*
 * Copyright 2026 Con Kolivas
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 3 of the License, or (at your option)
 * any later version.  See COPYING for more details.
 */

#include "config.h"

#include <isa-l.h>
#include <string.h>

#include "ckp2p_fec.h"

int p2p_fec_repair_count(int k)
{
	int m;

	if (k < 1)
		k = 1;
	m = (k + 1) / 2;
	if (m < 2)
		m = 2;
	return m;
}

int p2p_fec_n(int k)
{
	int n;

	if (k < 1)
		k = 1;
	n = k + p2p_fec_repair_count(k);
	if (n > P2P_FEC_MAX_N)
		n = P2P_FEC_MAX_N;
	return n;
}

int p2p_fec_k_for_bytes(uint32_t len)
{
	int k;

	if (!len)
		return 1;
	k = (int)((len + P2P_FEC_SHARD - 1) / P2P_FEC_SHARD);
	if (k < 1)
		k = 1;
	if (k > P2P_FEC_MAX_K)
		k = P2P_FEC_MAX_K;
	return k;
}

bool p2p_fec_encode(const uchar *data, uint32_t len, int k, int n, uchar **out)
{
	uchar *matrix, *g_tbls;
	int i, p, off;
	bool ret = false;

	if (k < 1 || n <= k || n > P2P_FEC_MAX_N || k > P2P_FEC_MAX_K || !out)
		return false;
	if (len > (uint32_t)k * P2P_FEC_SHARD)
		return false;

	p = n - k;
	matrix = ckzalloc((size_t)n * k);
	g_tbls = ckzalloc((size_t)32 * k * p);

	for (i = 0; i < k; i++) {
		memset(out[i], 0, P2P_FEC_SHARD);
		off = i * P2P_FEC_SHARD;
		if ((uint32_t)off < len) {
			uint32_t chunk = len - off;

			if (chunk > P2P_FEC_SHARD)
				chunk = P2P_FEC_SHARD;
			memcpy(out[i], data + off, chunk);
		}
	}
	for (i = k; i < n; i++)
		memset(out[i], 0, P2P_FEC_SHARD);

	gf_gen_cauchy1_matrix(matrix, n, k);
	ec_init_tables(k, p, matrix + k * k, g_tbls);
	ec_encode_data(P2P_FEC_SHARD, k, p, g_tbls, out, out + k);
	ret = true;

	dealloc(matrix);
	dealloc(g_tbls);
	return ret;
}

bool p2p_fec_decode(uchar **in, const unsigned *idxs, int got, int k, int n,
		    uchar *out, uint32_t len)
{
	uchar *matrix, *b, *inv, *g_tbls;
	uchar *data_ptrs[P2P_FEC_MAX_K], *recov[P2P_FEC_MAX_K];
	uchar *recovered, *rec_store[P2P_FEC_MAX_K];
	int i, j, used;
	unsigned used_idx[P2P_FEC_MAX_K];
	bool have_data[P2P_FEC_MAX_K] = {};
	bool ret = false;

	if (k < 1 || n <= k || got < k || !in || !idxs || !out)
		return false;
	if (len > (uint32_t)k * P2P_FEC_SHARD)
		return false;

	used = 0;
	for (i = 0; i < got && used < k; i++) {
		bool dup = false;

		if (idxs[i] >= (unsigned)n)
			continue;
		for (j = 0; j < used; j++) {
			if (used_idx[j] == idxs[i]) {
				dup = true;
				break;
			}
		}
		if (dup)
			continue;
		used_idx[used] = idxs[i];
		recov[used] = in[i];
		if (idxs[i] < (unsigned)k)
			have_data[idxs[i]] = true;
		used++;
	}
	if (used < k)
		return false;

	/* Fast path: all systematic data shards present */
	for (i = 0; i < k; i++) {
		if (!have_data[i])
			break;
	}
	if (i == k) {
		uchar *by_idx[P2P_FEC_MAX_K] = {};

		for (j = 0; j < used; j++) {
			if (used_idx[j] < (unsigned)k)
				by_idx[used_idx[j]] = recov[j];
		}
		for (i = 0; i < k; i++) {
			uint32_t off = (uint32_t)i * P2P_FEC_SHARD;
			uint32_t chunk;

			if (off >= len)
				break;
			chunk = len - off;
			if (chunk > P2P_FEC_SHARD)
				chunk = P2P_FEC_SHARD;
			if (!by_idx[i])
				return false;
			memcpy(out + off, by_idx[i], chunk);
		}
		return true;
	}

	matrix = ckzalloc((size_t)n * k);
	b = ckzalloc((size_t)k * k);
	inv = ckzalloc((size_t)k * k);
	g_tbls = ckzalloc((size_t)32 * k * k);
	recovered = ckzalloc((size_t)k * P2P_FEC_SHARD + 32);

	gf_gen_cauchy1_matrix(matrix, n, k);
	for (i = 0; i < k; i++)
		memcpy(b + i * k, matrix + used_idx[i] * k, k);
	if (gf_invert_matrix(b, inv, k))
		goto out;

	for (i = 0; i < k; i++) {
		uintptr_t base = (uintptr_t)recovered;

		base = (base + 31) & ~(uintptr_t)31;
		rec_store[i] = (uchar *)base + (size_t)i * P2P_FEC_SHARD;
		data_ptrs[i] = recov[i];
	}

	ec_init_tables(k, k, inv, g_tbls);
	ec_encode_data(P2P_FEC_SHARD, k, k, g_tbls, data_ptrs, rec_store);

	for (i = 0; i < k; i++) {
		uint32_t off = (uint32_t)i * P2P_FEC_SHARD;
		uint32_t chunk;

		if (off >= len)
			break;
		chunk = len - off;
		if (chunk > P2P_FEC_SHARD)
			chunk = P2P_FEC_SHARD;
		memcpy(out + off, rec_store[i], chunk);
	}
	ret = true;
out:
	dealloc(matrix);
	dealloc(b);
	dealloc(inv);
	dealloc(g_tbls);
	dealloc(recovered);
	return ret;
}
