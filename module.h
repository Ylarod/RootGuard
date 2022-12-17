#include "linux/compiler.h"
#include <linux/cpu.h>
#include <linux/memory.h>
#include <linux/uaccess.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <linux/fs.h>
#include <asm-generic/errno-base.h>

#ifdef pr_fmt
#undef pr_fmt
#define pr_fmt(fmt) "RootGuard: " fmt
#endif

#define MAX_ARG_STRINGS 0x7FFFFFFF

uintptr_t kprobe_get_addr(const char *symbol_name) {
    int ret;
    struct kprobe kp;
    uintptr_t tmp = 0;
    kp.addr = 0;
    kp.symbol_name = symbol_name;
    ret = register_kprobe(&kp);
    tmp = (uintptr_t)kp.addr;
    if (ret < 0) {
        goto out; // not function, maybe symbol
    }
    unregister_kprobe(&kp);
out:
    return tmp;
}

struct user_arg_ptr {
#ifdef CONFIG_COMPAT
	bool is_compat;
#endif
	union {
		const char __user *const __user *native;
#ifdef CONFIG_COMPAT
		const compat_uptr_t __user *compat;
#endif
	} ptr;
};

static const char __user *get_user_arg_ptr(struct user_arg_ptr argv, int nr)
{
	const char __user *native;

#ifdef CONFIG_COMPAT
	if (unlikely(argv.is_compat)) {
		compat_uptr_t compat;

		if (get_user(compat, argv.ptr.compat + nr))
			return ERR_PTR(-EFAULT);

		return compat_ptr(compat);
	}
#endif

	if (get_user(native, argv.ptr.native + nr))
		return ERR_PTR(-EFAULT);

	return native;
}

/*
 * count() counts the number of strings in array ARGV.
 */
static int count(struct user_arg_ptr argv, int max){
	int i = 0;
	if (argv.ptr.native != NULL) {
		for (;;) {
			const char __user *p = get_user_arg_ptr(argv, i);
			if (!p)
				break;
			if (IS_ERR(p))
				return -EFAULT;
			if (i >= max)
				return -E2BIG;
			++i;
		}
	}
	return i;
}
