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
 * symbolic name using /proc/kallsyms
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
	__u64 start;
	__u64 end;
	LIST_ENTRY(symbol_entry) list;
};

LIST_HEAD(sym_list, symbol_entry);

/*
 * This is our cache of symbols that we've previously looked up
 */ 
static struct sym_list sym_list_head = {NULL}; 


static int lookup_kas_cache( __u64 pc, struct loc_result *location)
{
	struct symbol_entry *sym;

	LIST_FOREACH(sym, &sym_list_head, list) {
		if ((pc >= sym->start) &&
		    (pc <= sym->end)) {
			location->symbol = sym->sym_name;
			location->offset = (pc - sym->start);
			return 0;
		}
	}

	return 1;
}

static void kas_add_cache(__u64 start, __u64 end, char *name)
{
	struct symbol_entry *sym = NULL;

	sym = malloc(sizeof(struct symbol_entry));
	if (!sym)
		return;

	sym->start = start;
	sym->end = end;
	sym->sym_name = name;

	LIST_INSERT_HEAD(&sym_list_head, sym, list);
	return;
}

static int lookup_kas_proc(__u64 pc, struct loc_result *location)
{
	FILE *pf;
	__u64 ppc;
	__u64 uppc, ulpc, uipc;
	char *name, *last_name;

	pf = fopen("/proc/kallsyms", "r");

	if (!pf)
		return 1;

	last_name = NULL;
	uipc = pc;
	while (!feof(pf)) {
		/* 
		 * Each line of /proc/kallsyms is formatteded as:
		 *  - "%pK %c %s\n" (for kernel internal symbols), or
		 *  - "%pK %c %s\t[%s]\n" (for module-provided symbols)
		 */
		fscanf(pf, "%llx %*s %as [ %*[^]] ]", &ppc, &name);
		uppc = (__u64)ppc;
		if ((uipc >= ulpc) &&
		    (uipc < uppc)) {
			/*
 			 * The last symbol we looked at
 			 * was a hit, record and return it
 			 * Note that we don't free last_name
 			 * here, because the cache is using it
 			 */
			kas_add_cache(ulpc, uppc-1, last_name);
			fclose(pf);
			free(name);
			return lookup_kas_cache(pc, location);
		} 

		/*
 		 * Advance all our state holders
 		 */
		free(last_name);
		last_name = name;
		ulpc = uppc;
	}

	fclose(pf);
	return 1;
}

static int lookup_kas_init(void)
{
	printf("Initalizing kallsyms db\n");
	
	return 0;
}


static int lookup_kas_sym(void *pc, struct loc_result *location)
{
	__u64 pcv;

	memset(&pcv, 0, sizeof(__u64));

	memcpy(&pcv, &pc, sizeof(void *));

	if (!lookup_kas_cache(pcv, location))
		return 0;

	return lookup_kas_proc(pcv, location);
}

struct lookup_methods kallsym_methods = {
	lookup_kas_init,
	lookup_kas_sym,
};

