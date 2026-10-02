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
	puts("sv2_proxy_jobs: all OK");
	return 0;
}
