/*
 * Copyright (C) 2009, Neil Horman <nhorman@redhat.com>
 * 
 * This program file is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; version 2 of the License.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program in a file named COPYING; if not, write to the
 * Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301 USA
 */

/*
 * This is a translator.  given an input address, this will convert it into a
 * function and offset.  Unless overridden, it will automatically determine
 * tranlations using the following methods, in order of priority:
 * 1) /usr/lib/debug/<kernel version> using libbfd
 * 2) /proc/kallsyms
 */

#include <stdlib.h>
#include <asm/types.h>


/*
 * Initalization routine
 * INPUTS:
 *   method - enum describing how to do translation
 *          * METHOD_NULL : Just print pc values, not symbols
 *          * METHOD_AUTO : automatic search for best method
 *          * METHOD_DEBUGINFO : use debuginfo package
 *          * METHOD_KALLSYMS : use /proc/kallsyms
 *   returns:
 *          * 0   : initalization succeded
 *          * < 0 : initalization failed
 */
typedef enum {
	METHOD_NULL = 0,
	METHOD_AUTO,
	METHOD_DEBUGINFO,
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


