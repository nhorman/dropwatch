/*
 * Copyright (C) 2009, Neil Horman <nhorman@redhat.com>
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
 * This is a translator.  given an input address, this will convert it into a
 * function and offset.  Unless overridden, it will automatically determine
 * translations using the following methods, in order of priority:
 * 1) /usr/lib/debug/<kernel version> using libbfd
 * 2) /proc/kallsyms
 */

#include "config.h"

#include <stdlib.h>
#include <asm/types.h>


/*
 * Initialization routine
 * INPUTS:
 *   method - enum describing how to do translation
 *          * METHOD_NULL : Just print pc values, not symbols
 *          * METHOD_AUTO : automatic search for best method
 *          * METHOD_DEBUGINFO : use debuginfo package
 *          * METHOD_KALLSYMS : use /proc/kallsyms
 *   returns:
 *          * 0   : initalization succeeded 
 *          * < 0 : initalization failed
 */
typedef enum {
	METHOD_NULL = 0,
	METHOD_AUTO,
#ifdef HAVE_BFD_H
	METHOD_DEBUGINFO,
#endif
	METHOD_KALLSYMS
} lookup_init_method_t;

struct loc_result {
	const char *symbol;
	__u64 offset;
};

int init_lookup(lookup_init_method_t method);
int lookup_symbol(void *pc, struct loc_result *location);

struct lookup_methods {
        int (*lookup_init)(void);
	int(*get_symbol)(void *pc, struct loc_result *location);
};


