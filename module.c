#include "module.h"
#include "asm/current.h"
#include "asm/string.h"
#include "linux/file.h"
#include "linux/gfp.h"
#include "linux/printk.h"
#include "linux/slab.h"
#include "linux/fs_struct.h"
#include <linux/namei.h>
#include <linux/dcache.h>

bool startswith(char* s, char* prefix) {
	return strncmp(s, prefix, strlen(prefix)) == 0;
}

bool endswith(const char *s, const char *t){
    size_t slen = strlen(s);
    size_t tlen = strlen(t);
    if (tlen > slen) return 1;
    return strcmp(s + slen - tlen, t) == 0;
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
	bool check = false;
	int i;
    if (IS_ERR(filename)) {
        return 0;
    }
	memcpy(&argv, (void*)&regs->regs[2], sizeof(struct user_arg_ptr));
	argc = count(argv, MAX_ARG_STRINGS);
	if (argc <= 0) {
		return 0;
	}
	if (endswith(filename->name, "/busybox")) {
		const char __user *p = get_user_arg_ptr(argv, 1);
		int len = strncpy_from_user(buf, p, 64);
		buf[63] = 0;
		if (len > 0) {
			if (strcmp(buf, "rm") == 0) {
				check = true;
			}
		}
	}
	if (endswith(filename->name, "/rm")) {
		check = true;
	}
	if (check) {
		for (i = 0; i < argc; i++) {
			int len;
			const char __user *p = get_user_arg_ptr(argv, i);
			len = strncpy_from_user(buf, p, 64);
			buf[63] = 0;
			if (len <= 0) {
				continue;
			}
			if (startswith(buf, "/")) {
				int j = 0;
				for (;;) {
					char* rm_protect_dir = rm_protect_dirs[j];
					if (rm_protect_dir == NULL) {
						break;
					}
					bool match_rule = false;
					if (strcmp(buf, rm_protect_dir) == 0) {
						match_rule = true;
					}
					if (strlen(buf) == strlen(rm_protect_dir) - 1) {
						match_rule = strncmp(buf, rm_protect_dir, strlen(rm_protect_dir) - 1) == 0;
					}
					if (match_rule) {
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

static int handler_pre_vfs_write(struct kprobe *p, struct pt_regs *regs) {
	if (current->cred->uid.val != 0) {
		return 0;
	}
 	char buf[128];
	struct file* f = (struct file*)regs->regs[0];
	struct path files_path = f->f_path;
	char *path = d_path(&files_path, buf, 128);
	buf[127] = 0;
	if (startswith(path, "/dev/block")) {
		pr_warn("deny: [%s] write to %s", current->comm, path);
		kill_pid(current->thread_pid, SIGKILL, 1);
	}
	if (startswith(path, "/dev") && strstr(path, ".magisk/block")) {
		pr_warn("deny: [%s] write to %s", current->comm, path);
		kill_pid(current->thread_pid, SIGKILL, 1);
	}
    return 0;
}

char* unlink_protect_dirs[] = {
	"/system/",
	"/system_ext/",
	"/vendor/",
	"/product/",
	NULL
};

static int handler_pre_do_unlinkat(struct kprobe *p, struct pt_regs *regs) {
	if (current->cred->uid.val != 0) {
		return 0;
	}
 	int dfd = regs->regs[0];
	// struct filename *name = (struct filename*)regs->regs[1];
	struct file *f = fget(dfd);
	char *buf = (char *)kmalloc(GFP_KERNEL, PATH_MAX);
	char *path;
	if (f != NULL) {
		path = d_path(&f->f_path, buf, PATH_MAX);
		int j = 0;
		for (;;) {
			char* protect_dir = unlink_protect_dirs[j];
			if (protect_dir == NULL) {
				break;
			}
			if (startswith(path, protect_dir)) {
				pr_warn("deny: [%s] unlinkat %s", current->comm, buf);
				kill_pid(current->thread_pid, SIGKILL, 1);
				return 0;
			}
			j++;
		}
	}
	// if (dfd == AT_FDCWD) {
	// 	// spin_lock(&current->fs->lock);
	// 	// path = d_path(&current->fs->pwd, buf, PATH_MAX);
	// 	// spin_unlock(&current->fs->lock);
	// 	path = (char*)name->name;
	// }
    return 0;
}

static struct kprobe kp_execve = {
    .symbol_name = "do_execveat_common",
    .pre_handler = handler_pre_execve,
};

static struct kprobe kp_vfs_write = {
    .symbol_name = "vfs_write",
    .pre_handler = handler_pre_vfs_write,
};

static struct kprobe kp_do_unlinkat = {
    .symbol_name = "do_unlinkat",
    .pre_handler = handler_pre_do_unlinkat,
};

int root_guard_init(void){
	pr_info("RootGuard init");
	register_kprobe(&kp_execve);
	register_kprobe(&kp_vfs_write);
	register_kprobe(&kp_do_unlinkat);
	return 0;
}

void root_guard_exit(void){
	pr_info("RootGuard exit");
	unregister_kprobe(&kp_execve);
	unregister_kprobe(&kp_vfs_write);
	unregister_kprobe(&kp_do_unlinkat);
}

module_init(root_guard_init);
module_exit(root_guard_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Ylarod");
MODULE_DESCRIPTION("A kernel module for protecting android rooted device");