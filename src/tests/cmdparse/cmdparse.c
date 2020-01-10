#include <sys/types.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include "../../src/util.h"
int
main(int argc, char **argv)
{
	char buf[LINE_MAX], **args;
	const char *p;
	int i, line;
	line = 1;
	while (fgets(buf, sizeof(buf), stdin) != NULL) {
		buf[strcspn(buf, "\r\n")] = '\0';
		if (strlen(buf) > 0) {
			fprintf(stdout, "%d -----\n", line++);
		}
		p = NULL;
		args = oddjob_parse_args(buf, &p);
		if (p != NULL) {
			fprintf(stderr, "%s\n", p);
		} else {
			if (args != NULL) {
				for (i = 0; args[i] != NULL; i++) {
					fprintf(stdout, "%s\n", args[i]);
				}
			}
		}
		if (args != NULL) {
			oddjob_free_args(args);
		}
	}
	return 0;
}
