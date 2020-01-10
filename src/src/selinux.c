/*
   Copyright 2005 Red Hat, Inc.
   All rights reserved.

   Redistribution and use in source and binary forms, with or without
   modification, are permitted provided that the following conditions are met:

    * Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in
      the documentation and/or other materials provided with the
      distribution.
    * Neither the name of Red Hat, Inc., nor the names of its
      contributors may be used to endorse or promote products derived
      from this software without specific prior written permission.

   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
   IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
   TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
   PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER
   OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
   EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
   PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
   PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
   LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
   NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
   SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "../config.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include <dbus/dbus.h>
#include "handlers.h"
#include "selinux.h"

#ifdef SELINUX_LABELS

#include <selinux/selinux.h>

#ifndef HAVE_MATCHPATHCON_INIT
static void
matchpathcon_init(const char *path) {
}
#endif

static dbus_bool_t
oddjob_check_selinux_enabled(void)
{
	static int selinux_enabled = -1;
	if (selinux_enabled == -1) {
		selinux_enabled = is_selinux_enabled();
		if (selinux_enabled == 1) {
			matchpathcon_init(NULL);
		}
	}
	return (selinux_enabled == 1);
}

void
oddjob_set_selinux_file_creation_context(const char *path, mode_t mode)
{
	security_context_t context;

	if (!oddjob_check_selinux_enabled()) {
		return;
	}

	context = NULL;
	if (matchpathcon(path, mode, &context) == 0) {
		if (context != NULL) {
			if (strcmp(context, "<<none>>") == 0) {
				oddjob_unset_selinux_file_creation_context();
			} else {
				setfscreatecon(context);
			}
			freecon(context);
		} else {
			oddjob_unset_selinux_file_creation_context();
		}
	}
}

void
oddjob_unset_selinux_file_creation_context(void)
{
	if (!oddjob_check_selinux_enabled()) {
		return;
	}
	setfscreatecon(NULL);
}

#else

void
oddjob_set_selinux_file_creation_context(const char *path, mode_t mode)
{
}

void
oddjob_unset_selinux_file_creation_context(void)
{
}

#endif

/* Create a directory with the given permissions, and create leading
 * directories as well.  Any directories which are created will have contexts
 * set as matchpathcon() dictates.  The directory itself will be owned by the
 * supplied uid and gid. */
int
oddjob_selinux_mkdir(const char *newpath, mode_t mode, uid_t uid, gid_t gid)
{
	char path[PATH_MAX + 1], tmp[PATH_MAX + 1];
	const char *p;
	char *q;
	int i;
	struct stat st;

	/* Collapse instances of "//" to "/". */
	if (strlen(newpath) < sizeof(tmp)) {
		strcpy(tmp, newpath);
		for (q = tmp; *q != '\0'; q++) {
			while ((q[0] == '/') &&
			       ((q[1] == '/') || (q[1] == '\0'))) {
				memmove(q, q + 1, strlen(q));
			}
		}
		newpath = tmp;
	}
	if (strlen(newpath) < sizeof(path)) {
		/* Walk the path name. */
		memset(path, '\0', sizeof(path));
		for (p = newpath; *p != '\0'; p++) {
			/* If the path so far non-empty, and the next char
			 * would be a directory separator, create the leading
			 * directory.  Accept EEXIST as the only okay error. */
			if ((p > newpath) && (*p == '/')) {
				/* Skip it if the directory exists. */
				if ((stat(path, &st) == 0) &&
				    (st.st_mode & S_IFDIR)) {
					path[p - newpath] = *p;
					continue;
				}
				/* Create the directory. */
				oddjob_set_selinux_file_creation_context(path,
									 S_IRWXU |
									 S_IXGRP |
									 S_IXOTH |
									 S_IFDIR);
				i = mkdir(path, S_IRWXU | S_IXGRP | S_IXOTH);
				oddjob_unset_selinux_file_creation_context();
				if ((i == -1) && (errno != EEXIST)) {
					syslog(LOG_ERR, "error creating %s: %m",
					       path);
					return HANDLER_FAILURE;
				}
			}
			path[p - newpath] = *p;
		}
		/* Now create the directory itself. */
		oddjob_set_selinux_file_creation_context(path, mode | S_IFDIR);
		i = mkdir(path, mode);
		oddjob_unset_selinux_file_creation_context();
		if ((i == -1) && (errno != EEXIST)) {
			syslog(LOG_ERR, "error creating %s: %m", path);
			return HANDLER_FAILURE;
		}
		if ((uid != (uid_t)-1) && (gid != (uid_t)-1)) {
			if (chown(path, uid, gid) != 0) {
				syslog(LOG_ERR, "error setting permissions on "
				       "%s: %m", path);
				rmdir(path);
				return HANDLER_FAILURE;
			}
		}
		return 0;
	} else {
		errno = EINVAL;
		syslog(LOG_ERR, "pathname (%s) is too long", newpath);
		return HANDLER_INVALID_INVOCATION;
	}
}
