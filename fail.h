/*
 * fail.h
 * Brandon Azad
 *
 * Error logging and termination.
 */
#ifndef PHYSMEM__FAIL_H_
#define PHYSMEM__FAIL_H_

#include <stdnoreturn.h>

/*
 * FAIL
 *
 * Description:
 * 	A macro to print an error message, clean up state, and exit.
 */
#define FAIL(fmt, ...)	fail("%s: " fmt "\n", __func__, ##__VA_ARGS__)

/*
 * fail
 *
 * Description:
 * 	Internal function used by FAIL. Do not call directly.
 */
void noreturn fail(const char *format, ...);

#endif
