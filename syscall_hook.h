/*
 * syscall_hook.h
 * Brandon Azad
 *
 * A system call hook allowing arbitrary kernel functions to be called with up to 5 arguments.
 */
#ifndef PHYSMEM__SYSCALL_HOOK_H_
#define PHYSMEM__SYSCALL_HOOK_H_

#include <stdint.h>

/*
 * syscall_hook_install
 *
 * Description:
 * 	Install a system call hook that allows us to call any function in the kernel with up to 5
 * 	arguments. The syscall hook should be uninstalled as soon as it is no longer needed.
 *
 * Dependencies:
 * 	kernel_init
 * 	physmem_init
 * 	probe_kernel_slide
 */
void syscall_hook_install(void);

/*
 * syscall_hook_remove
 *
 * Description:
 * 	Remove the system call hook. It is safe to call this function even when the syscall hook is
 * 	not installed.
 */
void syscall_hook_remove(void);

/*
 * kernel_call
 *
 * Description:
 * 	Call the given kernel function with up to 5 arguments.
 */
uint64_t kernel_call(uint64_t func,
		uint64_t arg1, uint64_t arg2, uint64_t arg3,
		uint64_t arg4, uint64_t arg5);

#endif
