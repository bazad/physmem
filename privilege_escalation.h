/*
 * privilege_escalation.h
 * Brandon Azad
 *
 * Privilege escalation using the physmem exploit.
 */
#ifndef PHYSMEM__PRIVILEGE_ESCALATION_H_
#define PHYSMEM__PRIVILEGE_ESCALATION_H_

/*
 * setuid_root
 *
 * Description:
 * 	Set the UID and GID of this process to 0.
 *
 * Dependencies:
 * 	kernel_init
 * 	physmem_init
 * 	probe_kernel_slide
 * 	syscall_hook_install
 */
void setuid_root(void);

#endif
