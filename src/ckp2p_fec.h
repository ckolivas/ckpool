/*
 * Copyright 2026 Con Kolivas
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 3 of the License, or (at your option)
 * any later version.  See COPYING for more details.
 */

#ifndef CKP2P_FEC_H
#define CKP2P_FEC_H

#include "libckpool.h"

/* 1344 is 32-byte aligned and leaves 44 bytes for the UDP MSG header
 * inside a 1400-byte datagram. */
#define P2P_FEC_SHARD	1344
#define P2P_FEC_MAX_K	32
#define P2P_FEC_MAX_N	48

int p2p_fec_repair_count(int k);
int p2p_fec_n(int k);
int p2p_fec_k_for_bytes(uint32_t len);

/* Encode `len` bytes into n systematic shards of P2P_FEC_SHARD (last data
 * shard zero-padded). out[i] must each have room for P2P_FEC_SHARD. */
bool p2p_fec_encode(const uchar *data, uint32_t len, int k, int n, uchar **out);

/* Reconstruct `len` data bytes from `got` shards (got >= k). idxs[i] is the
 * symbol index of in[i]. */
bool p2p_fec_decode(uchar **in, const unsigned *idxs, int got, int k, int n,
		    uchar *out, uint32_t len);

#endif
