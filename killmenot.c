#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kallsyms.h>
#include <linux/limits.h>
#include <linux/module.h>
#include <linux/mm_types.h>
#include <linux/sched.h>
#include <linux/security.h>

MODULE_LICENSE("GPL");

#define KMNOT_BANNER		"[" KBUILD_MODNAME "]: "
#define kmnot_err(...)		pr_err(KMNOT_BANNER __VA_ARGS__)
#define kmnot_warn(...)		pr_warn(KMNOT_BANNER __VA_ARGS__)
#define kmnot_info(...)		pr_info(KMNOT_BANNER __VA_ARGS__)
#define kmnot_debug(...)	pr_debug(KMNOT_BANNER __VA_ARGS__)

/* Max number of user programs watched */
#define KMNOT_PROGLIST_MAX	(16)

static char *proglist[KMNOT_PROGLIST_MAX];
static int proglist_len = ARRAY_SIZE(proglist);
module_param_array(proglist, charp, &proglist_len, 0);
MODULE_PARM_DESC(proglist, "Comma-separated list of full "
			   "program names with absolute path");

/* Buffer to store a full filename derived from task_struct{} */
static char *path_buf;
DEFINE_SPINLOCK(path_spinlock);

/* Full list of signals that we react to. Complete if necessary. */
#define KMNOT_SIGMASK						\
	(sigmask(SIGKILL) | sigmask(SIGINT) | sigmask(SIGTERM))
static sigset_t kmnot_sigset;

/* Forward declarations */
void kmnot_task_free(struct task_struct *task);
int  kmnot_task_kill(struct task_struct *task,
		     struct siginfo *info, int sig, u32 secid);
int  kmnot_task_wait(struct task_struct *task);

/* Places to store original and new function pointers */
static struct security_operations kern_secops;
static struct security_operations kmnot_secops = {
	.task_kill	= kmnot_task_kill,
};

/* Structure to store the address of a found kernel symbol */
typedef struct kmnot_symdata {
	unsigned long	addr;
	char 		*name;
} kmnot_symdata_t;

kmnot_symdata_t kmnot_symdata_secops = { .name = "security_ops" };

static int kmnot_kallsyms_cb(kmnot_symdata_t *symdata, const char *name,
			     struct module *mod, unsigned long addr) 
{
	if (name && symdata->name && !strcmp(name, symdata->name)) {
		symdata->addr = addr;
		return 1;
	}
	return 0;
}

static int kmnot_address_by_symbol(kmnot_symdata_t *symdata)
{
	if (!kallsyms_on_each_symbol((void *)kmnot_kallsyms_cb, symdata))
		return -EFAULT;
	return 0;
}
/*
 * The way this function works is wrong. We can't just compare program
 * names and be sure that we restrict forceful termination of a program.
 * What if it's run through a hard link? Or a symlink?
 * It appears that we need to work with inodes. List of programs given
 * to the module should be normalized down to inode and FS for each
 * program, be that a hard link, symlink, or an orginal executable.
 * Then we should check for this data in the function.
 *
 * XXX What if an executable was simply copied to a new executable file?
 */
int kmnot_task_kill(struct task_struct *task,
		    struct siginfo *info, int sig, u32 secid)
{
	int i;
	char *path = task->comm;
	struct mm_struct *mm = task->mm;

	kmnot_debug("%s: pid=%d, path=\"%s\", sig=%d\n",
		   __FUNCTION__, task->pid, task->comm, sig);

	/*
	 * Protect filling and accessing of 'path_buf'. Actually, this appears
	 * to run in atomic context, so I'm not sure that a lock is required.
	 */ 
	spin_lock(&path_spinlock);
	if (mm && mm->exe_file) {
		/*
		 * If it's a symlink, this gets the actual full filename
		 */
		path = d_path(&mm->exe_file->f_path, path_buf, PATH_MAX);
	}
	kmnot_debug("%s: path=\"%s\"\n", __FUNCTION__, path);

	for (i = 0; i < proglist_len; i++) {
		if (!strcmp(path, proglist[i])) {
			if (!sigismember(&kmnot_sigset, sig))
				break;
			kmnot_err("Attempt to kill "
				  "a restricted program: %s\n", path);
			spin_unlock(&path_spinlock);
			return -EPERM;
		}
	}
	spin_unlock(&path_spinlock);

	if (kern_secops.task_kill)
		return (*kern_secops.task_kill)(task, info, sig, secid);

	return 0;
}

static int __init kmnot_init(void)
{
	int i;
	struct security_operations *secops;

	if (proglist[0] == NULL) {
		kmnot_err("Mandatory list of restricted programs missing.\n");
		return -EFAULT;
	}
	for (i = 0; i < proglist_len; i++)
		kmnot_info("Restricted program: \"%s\"\n", proglist[i]);

	if (kmnot_address_by_symbol(&kmnot_symdata_secops)) {
		kmnot_err("Unable to obtain address of \"%s\"\n",
			  kmnot_symdata_secops.name);
		return -EFAULT;
	}
	if ((path_buf = kmalloc(PATH_MAX, GFP_KERNEL)) == NULL) {
		kmnot_err("Unable to allocate memory for path buffer\n");
		return -EFAULT;
	}
	sigaddsetmask(&kmnot_sigset, KMNOT_SIGMASK);
	secops = *(struct security_operations **)kmnot_symdata_secops.addr;
	kern_secops.task_kill = secops->task_kill;
	secops->task_kill = kmnot_secops.task_kill;

	kmnot_info("Service started\n");

	return 0;
}

static void __exit kmnot_exit(void)
{
	struct security_operations *secops =
		*(struct security_operations **)kmnot_symdata_secops.addr;
	secops->task_kill = kern_secops.task_kill;

	kfree(path_buf);

	kmnot_info("Service finished\n");
}

module_init(kmnot_init);
module_exit(kmnot_exit);
