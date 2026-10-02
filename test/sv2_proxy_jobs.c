/* Copyright 2026 Con Kolivas. Upstream job target/lifetime regressions. */
#include "config.h"
#include <assert.h>
#include "../src/generator.c"

ckpool_t ckpool;

void logmsg(int __maybe_unused level, const char __maybe_unused *fmt, ...) {}
void sv2_jdc_template_put(struct sv2_jdc_template __maybe_unused *t) {}

int main(void)
{
	struct sv2_proxy sp = {0};
	struct sv2_proxy_job job = {0};

	job.future = true;
	job.diff = 100;
	sp.target_diff = 400;
	sp.snph_min_ntime = 1000;
	sv2_proxy_activate_job(&sp, &job);
	assert(!job.future && job.diff == 400 && job.min_ntime == 1000);
	sp.target_diff = 50;
	sp.snph_min_ntime = 1001;
	sv2_proxy_activate_job(&sp, &job);
	assert(job.diff == 400 && job.min_ntime == 1000);
	{
		struct sv2_submit_shares_success ok = {0};
		double diff;
		unsigned int i;

		assert(sv2_proxy_track_share(&sp, 10, 100, 1, 1));
		assert(sv2_proxy_track_share(&sp, 11, 400, 1, 1));
		ok.last_sequence_number = 11;
		ok.new_submits_accepted_count = 1;
		ok.new_shares_sum = 400;
		assert(sv2_proxy_accept_batch(&sp, &ok, 2));
		assert(sp.unanswered == 1 && HASH_COUNT(sp.pending) == 2);
		assert(sv2_proxy_reject_share(&sp, 10, &diff, 3) && diff == 100);
		assert(!sp.pending && !sp.unanswered);
		assert(!sv2_proxy_accept_batch(&sp, &ok, 4));
		for (i = 0; i < SV2_PROXY_MAX_UNANSWERED; i++)
			assert(sv2_proxy_track_share(&sp, i, 1, 1, 5));
		assert(!sv2_proxy_track_share(&sp, i, 1, 1, 5));
		ok.new_submits_accepted_count = SV2_PROXY_MAX_UNANSWERED;
		assert(sv2_proxy_accept_batch(&sp, &ok, 6));
		assert(!sp.pending);
		assert(sv2_proxy_track_share(&sp, UINT32_MAX, 1, 1, 7));
		assert(!sv2_proxy_track_share(&sp, 0, 1, 1, 7 + SV2_PROXY_ACK_TIMEOUT));
		assert(sv2_proxy_reject_share(&sp, UINT32_MAX, &diff, 8));
		assert(sv2_proxy_track_share(&sp, UINT32_MAX, 1, 1, 9));
		ok.new_submits_accepted_count = 1;
		for (i = 0; i <= SV2_PROXY_SHARE_HISTORY; i++) {
			assert(sv2_proxy_track_share(&sp, i, 1, 1, 9));
			assert(sv2_proxy_accept_batch(&sp, &ok, 9));
			assert(HASH_COUNT(sp.pending) <= SV2_PROXY_SHARE_HISTORY);
		}
		assert(!sv2_proxy_reject_share(&sp, UINT32_MAX, &diff, 9));
		assert(sv2_proxy_accept_batch(&sp, &ok, 9));
		assert(!sp.pending && !sp.unanswered);
	}
	{
		struct sv2_proxy_job *old, *current;

		old = sv2_proxy_job_slot(&sp, 7);
		old->version = 1;
		old->coinb1 = ckalloc(1);
		sv2_proxy_job_slot(&sp, 8)->version = 2;
		current = sv2_proxy_job_slot(&sp, 7);
		current->version = 3;
		assert(sv2_proxy_find_job(&sp, 7) == current);
		assert(current->version == 3 && !current->coinb1);
		sv2_proxy_invalidate_jobs(&sp, current);
		assert(!sv2_proxy_find_job(&sp, 8));
		assert(sv2_proxy_find_job(&sp, 7) == current);
		sv2_proxy_invalidate_jobs(&sp, NULL);
	}
	puts("sv2_proxy_jobs: all OK");
	return 0;
}
