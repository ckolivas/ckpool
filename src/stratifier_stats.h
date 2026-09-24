/*
 * Copyright 2026 Con Kolivas
 *
 * Rejected difficulty is untrusted accounting: a miner can request a very
 * high difficulty and submit invalid work without doing the corresponding PoW.
 */
#ifndef STRATIFIER_STATS_H
#define STRATIFIER_STATS_H

#include <stdint.h>

/* Saturate both the pending batch and the round total. Never add in floating
 * point: even INT64_MAX + 0 rounds to 2^63 as a double, making a cast undefined.
 * A negative total restored from an older overflow cannot be recovered. */
static inline int64_t add_rejects(int64_t total, int64_t diff)
{
	if (total < 0)
		total = 0;
	if (diff <= 0)
		return total;
	if (diff > INT64_MAX - total)
		return INT64_MAX;
	return total + diff;
}

static inline int64_t add_reject_diff(int64_t total, double diff)
{
	if (!(diff > 0)) /* Includes NaN. */
		return add_rejects(total, 0);
	/* (double)INT64_MAX rounds up to 2^63, the first invalid conversion. */
	if (diff >= 0x1p63)
		return INT64_MAX;
	return add_rejects(total, (int64_t)diff);
}

#endif /* STRATIFIER_STATS_H */
