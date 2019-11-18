/*
 * Copyright (C) 2009, Neil Horman <nhorman@redhat.com>
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
 * This is a translator.  given an input address, this will convert it into a
 * symbollic name using the bfd library
 */

#include "config.h"

#include <stdlib.h>
#include <stdio.h>
#include <sys/utsname.h>
#include <bfd.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "lookup.h"


static int lookup_bfd_init(void)
{
	struct utsname uts;
	struct stat sb;
	char *dbibuf;

	/*
	*Start by determining if we have the required debuginfo package
	*here
	*/
	if(uname(&uts)<0)
		return-1;

	dbibuf = malloc(strlen("/usr/lib/debug/lib/modules") + strlen(uts.release) + 1);
	sprintf(dbibuf,"/usr/lib/debug/lib/modules/%s", uts.release);
	if (stat(dbibuf,&sb) < 0) {
		free(dbibuf);
		goto out_fail;
	}

	free(dbibuf);


	bfd_init();
	return 0;

out_fail:
	return-1;
}

static int lookup_bfd_sym(void *pc, struct loc_result *location)
{
	return 1;
}

struct lookup_methods bfd_methods = {
	lookup_bfd_init,
	lookup_bfd_sym,
};
