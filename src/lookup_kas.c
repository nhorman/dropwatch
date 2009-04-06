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
 * symbollic name using /proc/kallsyms
 */

#include <stdlib.h>
#include <stdio.h>
#include <sys/utsname.h>
#include <bfd.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/queue.h>

#include "lookup.h"

struct symbol_entry {
	char *sym_name;
	unsigned long long location;
	LIST_ENTRY(symbol_entry) list;
};

LIST_HEAD(sym_list, symbol_entry);

/*
 * This is our cache of symbols that we've previously looked up
 */ 
static struct sym_list sym_list_head = {NULL}; 

static int lookup_kas_init(void)
{
	printf("Initalizing kallsyms db\n");
	
	return 0;
}


static char *lookup_kas_sym(void *pc)
{
	return NULL;
}

struct lookup_methods kallsym_methods = {
	lookup_kas_init,
	lookup_kas_sym,
};

