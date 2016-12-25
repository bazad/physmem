/*
 * kernel_slide.h
 * Brandon Azad
 *
 * Find the kernel slide using the physmem exploit.
 */
#ifndef PHYSMEM__KERNEL_SLIDE_H_
#define PHYSMEM__KERNEL_SLIDE_H_

#include <stdint.h>

/*
 * kernel_slide
 *
 * Description:
 * 	The kASLR slide, or 0 if the slide has not yet been found.
 */
extern uint64_t kernel_slide;

/*
 * probe_kernel_slide
 *
 * Description:
 * 	Find the kernel slide.
 *
 * Dependencies:
 * 	kernel_init
 * 	physmem_init
 */
void probe_kernel_slide(void);

#endif
