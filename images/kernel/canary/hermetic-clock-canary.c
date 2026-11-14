// SPDX-License-Identifier: GPL-2.0
/* Test kernel only. Never stage this kernel in a benchmark world. */
#include <linux/init.h>
#include <linux/errno.h>
#include <linux/kvm_para.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/printk.h>
#include <asm/io.h>
#include <asm/msr.h>

static bool nested_canary;
static int __init canary_opt_in(char *value)
{
	nested_canary = value && !strcmp(value, "nested-vm");
	return 0;
}
early_param("hermetic.clock_canary", canary_opt_in);

static int __init hermetic_clock_canary(void)
{
	static const u32 msrs[] = { 0x11, 0x12, 0x4b564d00, 0x4b564d01 };
	unsigned long page;
	phys_addr_t gpa;
	bool passed = true, retained = false;
	unsigned int i;
	long result;

	if (!nested_canary)
		return 0;
	page = __get_free_page(GFP_KERNEL);
	if (!page) {
		pr_info("hermetic-canary/v1 error=allocation\n");
		return 0;
	}
	gpa = virt_to_phys((void *)page);
	/* Periodic MSR registration and removal belong to the same vCPU. */
	migrate_disable();
	for (i = 0; i < ARRAY_SIZE(msrs); i++) {
		u64 value = 0;
		bool system = msrs[i] == 0x12 || msrs[i] == 0x4b564d01;
		int rd, wr;
		bool unchanged;

		memset((void *)page, 0xa5, PAGE_SIZE);
		rd = rdmsrl_safe(msrs[i], &value);
		wr = wrmsrl_safe(msrs[i], gpa | (system ? 1 : 0));
		/* Disable accepted periodic updates before inspecting/freeing the page. */
		if (!wr && system && wrmsrl_safe(msrs[i], 0))
			retained = true;
		unchanged = !memchr_inv((void *)page, 0xa5, PAGE_SIZE);
		passed &= rd != 0 && wr != 0 && unchanged;
		pr_info("hermetic-canary/v1 msr=%08x rd=%s wr=%s page=%s\n",
			msrs[i], rd ? "gp" : "accepted", wr ? "gp" : "accepted",
			unchanged ? "unchanged" : "changed");
	}
	memset((void *)page, 0xa5, PAGE_SIZE);
	result = kvm_hypercall2(KVM_HC_CLOCK_PAIRING, gpa, KVM_CLOCK_PAIRING_WALLCLOCK);
	passed &= result == -ENOSYS && !memchr_inv((void *)page, 0xa5, PAGE_SIZE);
	pr_info("hermetic-canary/v1 hypercall=9 ret=%s page=%s\n",
		result == -ENOSYS ? "enosys" : "unexpected",
		!memchr_inv((void *)page, 0xa5, PAGE_SIZE) ? "unchanged" : "changed");
	pr_info("hermetic-canary/v1 result=%s\n", passed ? "pass" : "fail");
	migrate_enable();
	/* A broken VMM must never retain a pointer to a freed page. */
	if (!retained)
		free_page(page);
	return 0;
}
late_initcall(hermetic_clock_canary);
