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
 * translations using the following methods, in order of priority:
 * 1) /usr/lib/debug/<kernel version> using libbfd
 * 2) /proc/kallsyms
 */

#include "config.h"

#include <stdlib.h>
#include <stdio.h>
#include <sys/utsname.h>
#ifdef HAVE_BFD_H
#include <bfd.h>
#endif
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "lookup.h"

#ifdef HAVE_BFD_H
extern struct lookup_methods bfd_methods;
#endif
extern struct lookup_methods kallsym_methods;

static int lookup_null_init(void)
{
	printf("Initializing null lookup method\n");
	return 0;
}

static int lookup_null_sym(void *pc, struct loc_result *location)
{
	/*
	 * In the null method, every lookup fails
	 */
	return 1;
}

static struct lookup_methods null_methods = {
	lookup_null_init,
        lookup_null_sym,
};

static struct lookup_methods *methods = NULL;

int init_lookup(lookup_init_method_t method)
{
	int rc;
	switch (method) {
	case METHOD_NULL:
		/*
 		 * Don't actually do any lookups,
 		 * just pretend everything is
 		 * not found
 		 */
		methods = &null_methods;
		break;
	case METHOD_AUTO:
#ifdef HAVE_BFD_H
		methods = &bfd_methods;
		if (methods->lookup_init() == 0)
			return 0;
#endif
		methods = &kallsym_methods;
		if (methods->lookup_init() == 0)
			return 0;
		methods = NULL;
		return -1;
#ifdef HAVE_BFD_H
	case METHOD_DEBUGINFO:
		methods = &bfd_methods;
		break;
#endif
	case METHOD_KALLSYMS:
		methods = &kallsym_methods;
		break;
	}

	rc = methods->lookup_init();
	if (rc < 0)
		methods = NULL;
	return rc;
}

int lookup_symbol(void *pc, struct loc_result *loc)
{
	if (loc == NULL)
		return 1;
	return methods->get_symbol(pc, loc);
}
