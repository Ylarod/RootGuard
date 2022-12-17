#include "module.h"
#include "linux/gfp.h"
#include "linux/printk.h"
#include "linux/slab.h"
#include <linux/namei.h>
#include <linux/dcache.h>

// kprobe 状态下若进入 __lookup_slow 会导致死机
static inline char* get_realpath(char* file, char* buf, int bufsize){
	struct path path;
	char* ptr;
	int err = kern_path(file, LOOKUP_FOLLOW, &path);
	if(!err) {
		ptr = d_path(&path, buf, bufsize);        
		if(!IS_ERR(ptr)) {
			return ptr;
		}
	}
	return NULL;
}

int startswith(char* s, char* prefix) {
	return strncmp(s, prefix, strlen(prefix));
}

int endswith(const char *s, const char *t){
    size_t slen = strlen(s);
    size_t tlen = strlen(t);
    if (tlen > slen) return 1;
    return strcmp(s + slen - tlen, t);
}

char* rm_protect_dirs[] = {
	"/",
	"/system/",
	"/system_ext/",
	"/data/",
	"/vendor/",
	"/product/",
	"/sdcard/",
	"/storage/emulated/0/",
	"/storage/sdcard/",
	NULL
};

// ---------------------------------------------------------

static int handler_pre_execve(struct kprobe *p, struct pt_regs *regs) {
	struct filename *filename = (struct filename *)regs->regs[1];
	struct user_arg_ptr argv;
	char buf[64];
	int argc;
	int i;
    if (IS_ERR(filename)) {
        return 0;
    }
	memcpy(&argv, (void*)&regs->regs[2], sizeof(struct user_arg_ptr));
	argc = count(argv, MAX_ARG_STRINGS);
	if (argc <= 0) {
		return 0;
	}
	if (strcmp(filename->name, "/system/bin/dd") == 0) {
		for (i = 0; i < argc; i++) {
			int len;
			const char __user *p = get_user_arg_ptr(argv, i);
			len = strncpy_from_user(buf, p, 64);
			buf[63] = 0;
			if (len > 0) {
				if (strstr(buf, "of=/dev/block")) {
					pr_warn("deny: [%s] dd of=/dev/block", current->comm);
					kill_pid(current->thread_pid, SIGKILL, 1);
				}
				if (strstr(buf, "of=") && strstr(buf, ".magisk/block")) {
					pr_warn("deny: [%s] dd of=/dev/block", current->comm);
					kill_pid(current->thread_pid, SIGKILL, 1);
				}
			}
		}
	}
	if (strcmp(filename->name, "/system/bin/rm") == 0) {
		for (i = 0; i < argc; i++) {
			int len;
			const char __user *p = get_user_arg_ptr(argv, i);
			len = strncpy_from_user(buf, p, 64);
			buf[63] = 0;
			if (len <= 0) {
				continue;
			}
			if (startswith(buf, "/") == 0) {
				int j = 0;
				for (;;) {
					char* rm_protect_dir = rm_protect_dirs[j];
					if (rm_protect_dir == NULL) {
						break;
					}
					if (strcmp(buf, rm_protect_dir) == 0 || 
							strncmp(buf, rm_protect_dir, strlen(rm_protect_dir) - 1) == 0) {
						pr_warn("deny: [%s] rm %s", current->comm, buf);
						kill_pid(current->thread_pid, SIGKILL, 1);
						return 0;
					}
					j++;
				}
			}
		}
	}
    return 0;
}

static int handler_pre_openat(struct kprobe *p, struct pt_regs *regs) {
	const char __user *filename = (const char __user *)regs->regs[1];
	// char rpath[256], *ptr;
	char* kname = kmalloc(PATH_MAX, GFP_KERNEL);
	int len;
	len = strncpy_from_user(kname, filename, PATH_MAX);
	if (unlikely(len < 0)) {
		kfree(kname);
		return 0;
	}
	// ptr = get_realpath(kname, rpath, 256);
	// if (ptr != NULL) {
	// 	pr_info("open: %s", ptr);
	// }else{
	// 	pr_err("error in realpath: %s", kname);
	// }
	// if (startswith(kname, "/dev/block") == 0) {
		
	// }
	kfree(kname);
    return 0;
}

static struct kprobe kp_execve = {
    .symbol_name = "do_execveat_common",
    .pre_handler = handler_pre_execve,
};

static struct kprobe kp_openat = {
    .symbol_name = "do_sys_openat2",
    .pre_handler = handler_pre_openat,
};

int root_guard_init(void){
	pr_info("RootGuard init");
	register_kprobe(&kp_execve);
	// register_kprobe(&kp_openat);
	return 0;
}

void root_guard_exit(void){
	pr_info("RootGuard exit");
	unregister_kprobe(&kp_execve);
	// unregister_kprobe(&kp_openat);
}

module_init(root_guard_init);
module_exit(root_guard_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Ylarod");
MODULE_DESCRIPTION("A kernel module for protecting android rooted device");