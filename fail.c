/*
 * fail.c
 * Brandon Azad
 *
 * Error logging and termination.
 */
#include "fail.h"

#include "syscall_hook.h"

#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

void noreturn fail(const char *format, ...) {
	static bool removing = false;
	va_list ap;
	va_start(ap, format);
	vfprintf(stderr, format, ap);
	va_end(ap);
	// Uninstall the syscall hook if this isn't a recursive failure.
	if (!removing) {
		removing = true;
		syscall_hook_remove();
	}
	exit(1);
}
