/*
 * kernel_image.h
 * Brandon Azad
 *
 * Kernel parsing functions.
 */
#ifndef PHYSMEM__KERNEL_IMAGE_H_
#define PHYSMEM__KERNEL_IMAGE_H_

#include "kernel_slide.h"

#include <stdlib.h>

/*
 * kernel_init
 *
 * Description:
 * 	Initialize the kernel image.
 *
 */
void kernel_init(void);

/*
 * kernel_symbol
 *
 * Description:
 * 	Find the address of the given kernel symbol. If kernel_slide is initialized, the address
 * 	returned will be the in-memory address. Otherwise the unslid address will be returned.
 */
uint64_t kernel_symbol(const char *symbol);

/*
 * kernel_search
 *
 * Description:
 * 	Search for the given byte sequence in the on-disk kernel image, and return the
 * 	corresponding in-memory address.
 */
uint64_t kernel_search(const void *data, size_t size);

#endif
