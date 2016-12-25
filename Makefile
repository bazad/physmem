all: physmem

FRAMEWORKS = -framework Foundation -framework IOKit

CFLAGS = -O3 -Wall -Wpedantic -Wno-gnu-folding-constant -Wno-gnu-zero-variadic-macro-arguments -Werror

SOURCES = fail.c \
	  kernel_image.c \
	  kernel_slide.c \
	  main.c \
	  physmem.c \
	  privilege_escalation.c \
	  syscall_hook.c \
	  syscall_hook.s

HEADERS = fail.h \
	  kernel_image.h \
	  kernel_slide.h \
	  physmem.h \
	  privilege_escalation.h \
	  syscall_code.h \
	  syscall_hook.h

physmem: $(SOURCES) $(HEADERS)
	$(CC) $(FRAMEWORKS) $(CFLAGS) $(SOURCES) -o $@

clean:
	rm -f -- physmem
