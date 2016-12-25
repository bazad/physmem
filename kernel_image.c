/*
 * kernel_image.c
 * Brandon Azad
 *
 * Kernel parsing functions.
 */
#include "kernel_image.h"

#include "fail.h"

#include <fcntl.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#define MIN_MACHO_SIZE  0x1000

/*
 * kernel_path
 *
 * Description:
 * 	The path to the kernel image.
 */
static const char *kernel_path = "/System/Library/Kernels/kernel";

/*
 * kernel
 *
 * Description:
 * 	The kernel image on disk.
 */
static const struct mach_header_64 *kernel;

/*
 * kernel_size
 *
 * Description:
 * 	The size of the kernel image. This is not currently used, but ideally would be used to make
 * 	macho_symtab and macho_string_index robust.
 */
static size_t kernel_size;

/*
 * kernel_symtab
 *
 * Description:
 * 	The LC_SYMTAB load command for the kernel.
 */
static const struct symtab_command *kernel_symtab;

/*
 * macho_symtab
 *
 * Description:
 * 	Find the symtab in the Mach-O image.
 */
static const struct symtab_command *
macho_symtab(const struct mach_header_64 *mh, size_t size) {
	const struct load_command *lc = (const struct load_command *)
		((uintptr_t)mh + sizeof(*mh));

	while ((uintptr_t)lc < (uintptr_t)mh + mh->sizeofcmds) {
		if (lc->cmd == LC_SYMTAB) {
			return (const struct symtab_command *)lc;
		}
		lc = (const struct load_command *)((uintptr_t)lc + lc->cmdsize);
	}
	return NULL;
}

/*
 * macho_string_index
 *
 * Description:
 * 	Find the index of the string in the string table.
 */
static uint64_t
macho_string_index(const struct mach_header_64 *mh, const struct symtab_command *symtab,
		const char *name) {
	uintptr_t base = (uintptr_t)mh + symtab->stroff;
	const char *str = (const char *)(base + 4);
	const char *end = (const char *)(base + symtab->strsize);
	uint64_t strx;
	for (;; str++) {
		strx = (uintptr_t)str - base;
		const char *p = name;
		for (;;) {
			if (str >= end) {
				return 0;
			}
			if (*p != *str) {
				while (str < end && *str != 0) {
					str++;
				}
				break;
			}
			if (*p == 0) {
				return strx;
			}
			p++;
			str++;
		}
	}
}

void kernel_init() {
	int fd = open(kernel_path, O_RDONLY);
	if (fd == -1) {
		FAIL("could not open %s", kernel_path);
	}
	struct stat st;
	int err = fstat(fd, &st);
	if (err == -1) {
		FAIL("could not stat %s", kernel_path);
	}
	if (st.st_size < MIN_MACHO_SIZE) {
		FAIL("%s too small", kernel_path);
	}
	kernel_size = (size_t)st.st_size;
	kernel = mmap(NULL, kernel_size, PROT_READ, MAP_SHARED, fd, 0);
	close(fd);
	if (kernel == MAP_FAILED) {
		FAIL("mmap %s failed", kernel_path);
	}
	if (kernel->magic != MH_MAGIC_64 || kernel->filetype != MH_EXECUTE) {
		FAIL("%s not a valid kernel", kernel_path);
	}
	kernel_symtab = macho_symtab(kernel, kernel_size);
	if (kernel_symtab == NULL) {
		FAIL("kernel symtab missing");
	}
}

uint64_t kernel_symbol(const char *name) {
	uint64_t strx = macho_string_index(kernel, kernel_symtab, name);
	if (strx == 0) {
		goto notfound;
	}
	const struct nlist_64 *nl = (const struct nlist_64 *)
		((uintptr_t)kernel + kernel_symtab->symoff);
	for (uint32_t i = 0; i < kernel_symtab->nsyms; i++) {
		if (nl[i].n_un.n_strx == strx) {
			if ((nl[i].n_type & N_TYPE) != N_SECT) {
				goto notfound;
			}
			return nl[i].n_value + kernel_slide;
		}
	}
notfound:
	FAIL("kernel symbol %s not found", name);
}

uint64_t kernel_search(const void *data, size_t size) {
	const struct load_command *lc = (const struct load_command *)
		((uintptr_t)kernel + sizeof(struct mach_header_64));
	const uintptr_t end = (uintptr_t)kernel + kernel->sizeofcmds;
	for (; (uintptr_t)lc < end;
	     lc = (const struct load_command *)((uintptr_t)lc + lc->cmdsize)) {
		if (lc->cmd != LC_SEGMENT_64) {
			continue;
		}
		const struct segment_command_64 *sc = (const struct segment_command_64 *)lc;
		const void *base = (const void *)((uintptr_t)kernel + sc->fileoff);
		const void *found = memmem(base, sc->filesize, data, size);
		if (found == NULL) {
			continue;
		}
		size_t offset = (uintptr_t)found - (uintptr_t)base;
		return sc->vmaddr + offset + kernel_slide;
	}
	FAIL("data not found in kernel");
}
