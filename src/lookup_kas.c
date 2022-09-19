/*
 * Copyright (C) 2009, Neil Horman <nhorman@redhat.com>
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
 * This is a translator.  given an input address, this will convert it into a
 * symbolic name using /proc/kallsyms
 */

#include "config.h"

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <sys/utsname.h>
#include <string.h>
#include <limits.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/queue.h>

#include "lookup.h"

struct symbol_entry {
	char *sym_name;
	uint64_t start;
	uint64_t end;
	LIST_ENTRY(symbol_entry) list;
};

LIST_HEAD(sym_list, symbol_entry);

/*
 * This is our cache of symbols that we've previously looked up
 */
static struct sym_list sym_list_head = {NULL};


static int lookup_kas_cache(uint64_t pc, struct loc_result *location)
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

static void kas_update_cache(__u64 start, __u64 end, char *name)
{
	struct symbol_entry *sym;
	/* look for any symbol that matches our start
 	 * if the new end is longer than the current end, extend it
 	 */
	LIST_FOREACH(sym, &sym_list_head, list) {
		if (start == sym->start) {
			if (end > sym->end) {
				sym->end = end;
			}
			return;
		}
	}

	/* if we get here, we didn't find a symbol, and should add it */
	kas_add_cache(start, end, name);
}

static int lookup_kas_proc(uint64_t pc, struct loc_result *location)
{
	FILE *pf;
	uint64_t sppc;
	uint64_t min_delta, sdelta;
	uint64_t sym_base_addr;
	char *tgt_sym = NULL;
	char *name;

	pf = fopen("/proc/kallsyms", "r");

	if (!pf)
		return 1;


	/*
 	 * We need to conduct a reverse price is right search here, we need to find the symbol that is less than 
 	 * pc, but by the least amount. i.e. address 0xffffffff00010 is 10 more than symbol A, at 0xffffffff00000000, 
 	 * but is only 8 more than symbol B at 0xffffffff00000002, therefore this drop occurs at symbol B+8
 	 */
	min_delta = LLONG_MAX;
	sym_base_addr = 0;
	while (!feof(pf)) {
		/*
		 * Each line of /proc/kallsyms is formatteded as:
		 *  - "%pK %c %s\n" (for kernel internal symbols), or
		 *  - "%pK %c %s\t[%s]\n" (for module-provided symbols)
		 */
		if (fscanf(pf, "%llx %*s %ms [ %*[^]] ]", (unsigned long long *)&sppc, &name) < 0) {
			if (ferror(pf)) {
				perror("Error Scanning File: ");
				break;
			}
			if (feof(pf)) {
				continue;
			}
		}

		/* don't bother with symbols that are above our target */
		if (sppc > pc) {
			continue;
		}

		sdelta = pc - sppc;
		if (sdelta < min_delta) {
			min_delta = sdelta;
			if (tgt_sym)
				free(tgt_sym);
			tgt_sym = strdup(name);
			sym_base_addr = sppc;
		}
		free(name);
	}

	fclose(pf);

	if (sym_base_addr) {
		kas_update_cache(sym_base_addr, sym_base_addr + min_delta, tgt_sym);
		location->symbol = tgt_sym;
		location->offset = min_delta;
		return 0;
	}
	return 1;
}

static int lookup_kas_init(void)
{
	printf("Initializing kallsyms db\n");

	return 0;
}

static int lookup_kas_sym(void *pc, struct loc_result *location)
{
	__u64 pcv;

	pcv = (uintptr_t)pc;

	if (!lookup_kas_cache(pcv, location)) {
		return 0;
	}

	return lookup_kas_proc(pcv, location);
}

struct lookup_methods kallsym_methods = {
	lookup_kas_init,
	lookup_kas_sym,
};
