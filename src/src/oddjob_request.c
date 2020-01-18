/*
   Copyright 2005,2006,2007 Red Hat, Inc.
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
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dbus/dbus.h>
#include "common.h"
#include "oddjob.h"
#define EXPECTED_ERROR "org.freedesktop.DBus.Error.ServiceUnknown"

int
main(int argc, char **argv)
{
	int i, arg, c, result;
	char outbuf[8192], errbuf[8192];
	const char *service, *object;
	char *interface, *method;
	const char *usage = "Usage: oddjob_request "
			    "[-S] [-s service] [-o object] [ [-i interface] "
			    "[request [arg1 [arg2 [arg3 [arg4]]]]] | -I ]";
	DBusBusType bus;

	/* If we got any options, assume that the user doesn't know how to call
	 * the program. */
	service = ODDJOB_SERVICE_NAME;
	object = ODDJOB_OBJECT_PATH;
	interface = ODDJOB_INTERFACE_NAME;
	method = NULL;
	bus = DBUS_BUS_SYSTEM;
	while ((c = getopt(argc, argv, "i:o:s:SI")) != -1) {
		switch (c) {
		case 'i':
			interface = optarg;
			break;
		case 'o':
			object = optarg;
			break;
		case 's':
			service = optarg;
			break;
		case 'S':
			bus = DBUS_BUS_SESSION;
			break;
		case 'I':
			interface = ODDJOB_INTROSPECTION_INTERFACE;
			method = ODDJOB_INTROSPECTION_METHOD;
			break;
		default:
			printf("%s\n", usage);
			exit(1);
			break;
		}
	}

	/* If we got no arguments, assume that they need help on using the
	 * program. */
	if ((argc == optind) && (method == NULL)) {
		printf("%s\n", usage);
	}

	/* Send the request as the user requested.  If they specified no
	 * request, then run the "list" method. */
	arg = optind;
	if (method == NULL) {
		if (argc > arg) {
			method = argv[arg++];
		}
		if (method != NULL) {
			if (strchr(method, '.') != NULL) {
				interface = malloc(strlen(method) + 1);
				if (interface != NULL) {
					strcpy(interface, method);
					method = strrchr(interface, '.');
					*method = '\0';
					method++;
				}
			}
		}
	}
	if (method == NULL) {
		method = "list";
	}
	i = oddjob_dbus_call_method(bus,
				    service,
				    object,
				    interface,
				    method,
				    &result,
				    outbuf, sizeof(outbuf),
				    errbuf, sizeof(errbuf),
				    (argc > (arg + 0)) ? argv[arg + 0] : NULL,
				    (argc > (arg + 1)) ? argv[arg + 1] : NULL,
				    (argc > (arg + 2)) ? argv[arg + 2] : NULL,
				    (argc > (arg + 3)) ? argv[arg + 3] : NULL,
				    NULL);

	if (i == 0) {
		/* If we ran the "list" method, and we got a response string,
		 * display it to the user. */
		if ((argc == optind) && (method == NULL)) {
			if (strlen(outbuf) > 0) {
				printf("Recognized requests: %s\n", outbuf);
			}
		} else {
			/* If it's introspection data, discard the error result
			 * which we never got. */
			if ((strcmp(interface,
				    ODDJOB_INTROSPECTION_INTERFACE) == 0) &&
			    (strcmp(method,
				    ODDJOB_INTROSPECTION_METHOD) == 0)) {
				result = 0;
			}
			/* Otherwise, if we got a result of any kind, display
			 * it to the user. */
			if (strlen(outbuf) > 0) {
				printf("%s", outbuf);
			}
			if (strlen(errbuf) > 0) {
				fprintf(stderr, "%s", errbuf);
			}
		}
	} else {
		fprintf(stderr, "%s\n", outbuf);
	}

	return result;
}
