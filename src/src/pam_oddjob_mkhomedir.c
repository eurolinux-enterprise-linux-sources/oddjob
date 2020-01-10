/*
   Copyright 2005,2007,2008 Red Hat, Inc.
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
#include <pwd.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <security/pam_modules.h>
#include "common.h"
#include "oddjob_dbus.h"

static void
conv_text_info(pam_handle_t *pamh, const char *info)
{
	struct pam_conv *conv;
	int i;
	conv = NULL;
	if ((pam_get_item(pamh, PAM_CONV, (const void**) &conv) == PAM_SUCCESS) &&
	    (conv != NULL)) {
		const struct pam_message message = {
			.msg_style = PAM_TEXT_INFO,
			.msg = info,
		};
		const struct pam_message *messages[] = {
			&message,
			NULL,
		};
		struct pam_response *responses;
		if (conv->conv != NULL) {
			responses = NULL;
			i = conv->conv(1, messages,
				       &responses, conv->appdata_ptr);
			if ((i == PAM_SUCCESS) && (responses != NULL)) {
				if (responses->resp != NULL) {
					free(responses->resp);
				}
				free(responses);
			}
		}
	}
}

static void
send_pam_oddjob_mkhomedir_request(pam_handle_t *pamh)
{
	const char *user;
	char *buf, reply[8192];
	size_t bufsize;
	struct passwd pwd, *pw;
	struct stat st;
	int ret, result;

	user = NULL;
	strcpy(reply, "");

	if ((pam_get_user(pamh, &user, "login: ") == PAM_SUCCESS) &&
	    (user != NULL) &&
	    (strlen(user) > 0)) {
		/* Attempt to look up information about the user. */
		bufsize = 4;
		do {
			pw = NULL;
			buf = malloc(bufsize);
			if (buf == NULL) {
				break;
			}
			ret = getpwnam_r(user, &pwd, buf, bufsize, &pw);
			if ((ret != 0) || (pw != &pwd)) {
				pw = NULL;
				free(buf);
				buf = NULL;
				if (errno == ERANGE) {
					bufsize += 4;
				} else {
					break;
				}
			}
		} while ((ret != 0) && (errno == ERANGE));
		if ((pw != NULL) &&
		    (stat(pw->pw_dir, &st) == -1) && (errno == ENOENT)) {
			/* If we're running with the user's privileges, then
			 * call the "mkmyhomedir" method. */
			if ((getuid() == pw->pw_uid) &&
			    (geteuid() == pw->pw_uid) &&
			    (getgid() == pw->pw_gid) &&
			    (getegid() == pw->pw_gid)) {
				ret = oddjob_dbus_call_method(DBUS_BUS_SYSTEM,
							      ODDJOB_SERVICE_NAME "_mkhomedir",
							      "/",
							      ODDJOB_INTERFACE_NAME "_mkhomedir",
							      "mkmyhomedir",
							      &result,
							      reply,
							      sizeof(reply),
							      NULL,
							      0,
							      NULL);
			} else {
				/* Otherwise, attempt to have a directory
				 * created for the user by calling the
				 * "mkhomedirfor" method. */
				ret = oddjob_dbus_call_method(DBUS_BUS_SYSTEM,
							      ODDJOB_SERVICE_NAME "_mkhomedir",
							      "/",
							      ODDJOB_INTERFACE_NAME "_mkhomedir",
							      "mkhomedirfor",
							      &result,
							      reply,
							      sizeof(reply),
							      NULL,
							      0,
							      user,
							      NULL);
			}
		}
		if (buf != NULL) {
			free(buf);
		}
	}

	if (strlen(reply) > 0) {
		conv_text_info(pamh, reply);
	}
}

int
pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	send_pam_oddjob_mkhomedir_request(pamh);
	return PAM_IGNORE;
}
int
pam_sm_close_session(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	return PAM_IGNORE;
}

int
pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	send_pam_oddjob_mkhomedir_request(pamh);
	return PAM_IGNORE;
}
