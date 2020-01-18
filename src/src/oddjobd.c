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
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <errno.h>
#include <fcntl.h>
#include <fnmatch.h>
#include <getopt.h>
#include <glob.h>
#include <grp.h>
#include <pwd.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dbus/dbus.h>
#include <libxml/xmlreader.h>
#ifdef SELINUX_ACLS
#include <selinux/selinux.h>
#include <selinux/context.h>
#include <selinux/flask.h>
#endif
#include "buffer.h"
#include "common.h"
#include "handlers.h"
#include "mainloop.h"
#include "oddjob_dbus.h"
#include "util.h"

#define ODDJOB_INTROSPECTION_HEADER \
"<!DOCTYPE node \n"\
"          PUBLIC \"-//freedesktop//DTD D-BUS Object Introspection 1.0//EN\"\n"\
"          \"http://www.freedesktop.org/standards/dbus/1.0/introspect.dtd\">\n"\
"<node>\n"
#define ODDJOB_INTROSPECTION_NODE \
"  <node name=\"%s\"/>\n"
#define ODDJOB_INTROSPECTION_INTERFACE_START \
"  <interface name=\"%s\">\n"
#define ODDJOB_INTROSPECTION_METHOD_START \
"    <method name=\"%s\">\n"
#define ODDJOB_INTROSPECTION_METHOD_ARGUMENT \
"      <arg direction=\"in\" type=\"s\"/>\n"
#define ODDJOB_INTROSPECTION_DBUS_METHOD_END \
"      <arg direction=\"out\" name=\"data\" type=\"s\"/>\n" \
"    </method>\n"
#define ODDJOB_INTROSPECTION_ODDJOB_METHOD_END \
"      <arg direction=\"out\" name=\"exit_status\" type=\"i\"/>\n" \
"      <arg direction=\"out\" name=\"stdout\" type=\"s\"/>\n" \
"      <arg direction=\"out\" name=\"stderr\" type=\"s\"/>\n" \
"    </method>\n"
#define ODDJOB_INTROSPECTION_INTERFACE_END \
"  </interface>\n"
#define ODDJOB_INTROSPECTION_FOOTER \
"</node>\n"

/* A structure which we use to keep track of outstanding requests. */
struct oddjob_async_task {
	pid_t pid;
	int stdin_fd, stdout_fd, stderr_fd;
	struct oddjob_buffer *stdin_buffer, *stdout_buffer, *stderr_buffer;
	struct oddjob_dbus_message *msg;
	char *service, *path, *interface, *method, *calling_user, **argv;
};

/* ACL entries. */
struct oddjob_acl {
	enum oddjob_acl_sense {
		oddjob_acl_default,
		oddjob_acl_allow,
		oddjob_acl_deny
	} sense;
	dbus_bool_t apply_user;
	char *user;
	dbus_bool_t apply_min_uid;
	unsigned long min_uid;
	dbus_bool_t apply_max_uid;
	unsigned long max_uid;
#ifdef SELINUX_ACLS
	dbus_bool_t apply_selinux_enforcing;
	dbus_bool_t selinux_enforcing;
	dbus_bool_t apply_selinux_context;
	char *selinux_context;
	dbus_bool_t apply_selinux_user;
	char *selinux_user;
	dbus_bool_t apply_selinux_role;
	char *selinux_role;
	dbus_bool_t apply_selinux_type;
	char *selinux_type;
	dbus_bool_t apply_selinux_range;
	char *selinux_range;
#endif
	struct oddjob_acl *next;
};

/* A structure which we use to keep track of configured methods. */
static struct {
	/* The parts of our configuration which are built from our
	 * configuration files. */
	struct oddjob_config {
		/* ACL for everything */
		struct oddjob_acl *acl;
		struct service {
			/* A well-known address / service name */
			char *name;
			struct oddjob_config *config;
			/* ACL for the service */
			struct oddjob_acl *acl;
			struct object {
				/* An object path */
				char *name;
				struct service *service;
				/* ACL for the object */
				struct oddjob_acl *acl;
				struct interface {
					/* An interface name */
					char *name;
					struct object *object;
					/* ACL for the interface */
					struct oddjob_acl *acl;
					struct method {
						/* A method name */
						char *name;
						struct interface *interface;
						/* ACL for the method */
						struct oddjob_acl *acl;
						/* Method type -- internal
						 * function, or external (call
						 * a helper) */
						enum method_type {
							method_invalid,
							method_internal,
							method_external,
						} type;
						int n_arguments;
						/* Function to call when the
						 * dbus layer passes us a
						 * method call */
						oddjob_dbus_handler *handler;
						/* Path of helper to exec,
						 * whether or not we prepend
						 * the caller's name to the
						 * list of arguments, and how
						 * we supply arguments, only
						 * applies to external methods
						 * */
						char **argv;
						dbus_bool_t prepend_user;
						enum oddjob_argument_passing_method {
							oddjob_argument_passing_invalid = 0,
							oddjob_argument_passing_stdin = 1,
							oddjob_argument_passing_cmdline = 2,
						} argument_passing_method;
					} *methods;
					int n_methods;
				} *interfaces;
				int n_interfaces;
			} *objects;
			int n_objects;
		} *services;
		int n_services;
	} *config;
	/* flags */
	int debug;
	int reload;
	int quit;
	const char *configfile;
#ifdef SELINUX_ACLS
	dbus_bool_t selinux_enabled, selinux_enforcing;
#endif
} globals = {
	.config = NULL,
	.debug = 0,
	.reload = 0,
	.quit = 0,
	.configfile = SYSCONFDIR "/" PACKAGE "d.conf",
#ifdef SELINUX_ACLS
	.selinux_enabled = FALSE,
	.selinux_enforcing = FALSE,
#endif
};

static void oddjobd_exec_method(struct oddjob_dbus_context *ctx,
				struct oddjob_dbus_message *msg,
				const char *service_name,
				const char *object_path,
				const char *interface_name,
				const char *method_name,
				const char *user,
				unsigned long uid,
				void *data);
static void oddjobd_reload_method(struct oddjob_dbus_context *ctx,
				  struct oddjob_dbus_message *msg,
				  const char *service_name,
				  const char *object_path,
				  const char *interface_name,
				  const char *method_name,
				  const char *user,
				  unsigned long uid,
				  void *data);
static dbus_bool_t load_config(struct oddjob_config *config,
			       const char *file, dbus_bool_t ignore_missing);
static void check_selinux_applicable(void);

#ifdef SELINUX_ACLS
/* Check if we have an SELinux match with the fields defined in this AC entry.
 * Assumes that check_selinux_applicable() was called at least relatively
 * recently, because one of those clauses matches whether or not we're in
 * enforcing mode. */
static dbus_bool_t
check_one_ac_selinux(struct oddjob_acl *acl, const char *selinux_context)
{
	char *ctx;
	const char *user, *role, *type, *range;
	dbus_bool_t ret;
	context_t context;

	/* If the ACL doesn't specify that we have to be in enforcing mode, and
	 * we're either in non-SELinux or permissive mode, then go ahead and
	 * return a success. */
	if (!acl->apply_selinux_enforcing &&
	    (!globals.selinux_enabled || !globals.selinux_enforcing)) {
		return TRUE;
	}
	/* Break the context up. */
	if (selinux_context != NULL) {
		context = context_new(selinux_context);
		ctx = context_str(context);
		user = context_user_get(context);
		role = context_role_get(context);
		type = context_type_get(context);
		range = context_range_get(context);
	} else {
		context = NULL;
		ctx = NULL;
		user = NULL;
		role = NULL;
		type = NULL;
		range = NULL;
	}
	/* Check all that apply. */
	ret = ((!acl->apply_selinux_enforcing) ||
	       (!acl->selinux_enforcing == !globals.selinux_enforcing)) &&
	      ((!acl->apply_selinux_context) ||
	       ((ctx != NULL) &&
		(fnmatch(acl->selinux_context, ctx,
			 ODDJOB_SECONTEXT_FNMATCH_FLAGS) == 0))) &&
	      ((!acl->apply_selinux_user) ||
	       ((user != NULL) &&
		(fnmatch(acl->selinux_user, user,
			 ODDJOB_SEUSER_FNMATCH_FLAGS) == 0))) &&
	      ((!acl->apply_selinux_role) ||
	       ((role != NULL) &&
		(fnmatch(acl->selinux_role, role,
			 ODDJOB_SEROLE_FNMATCH_FLAGS) == 0))) &&
	      ((!acl->apply_selinux_type) ||
	       ((type != NULL) &&
		(fnmatch(acl->selinux_type, type,
			 ODDJOB_SETYPE_FNMATCH_FLAGS) == 0))) &&
	      ((!acl->apply_selinux_range) ||
	       ((range != NULL) &&
		(fnmatch(acl->selinux_range, range,
			 ODDJOB_SERANGE_FNMATCH_FLAGS) == 0)));
	/* Free the decomposed context.  The other strings are "owned" by this
	 * structure. */
	if (context != NULL) {
		context_free(context);
	}
	return ret;
}
#else
/* Ignore SELinux rules, no matter what. */
static dbus_bool_t
check_one_ac_selinux(struct oddjob_acl *acl, const char *selinux_context)
{
	return TRUE;
}
#endif

/* Check if a single AC entry matches the given user and UID. */
static dbus_bool_t
check_one_ac_match(struct oddjob_acl *acl, const char *user, unsigned long uid,
		   const char *selinux_context)
{
	return ((!acl->apply_user) ||
		(fnmatch(acl->user, user, ODDJOB_USER_FNMATCH_FLAGS) == 0)) &&
	       ((!acl->apply_min_uid) || (uid >= acl->min_uid)) &&
	       ((!acl->apply_max_uid) || (uid <= acl->max_uid)) &&
	       check_one_ac_selinux(acl, selinux_context);
}

/* Check if there is a match for the given user, UID, and/or security context
 * somewhere in the given ACL, returning "allow" if there's an access rule
 * which allows the user acces, "deny" if there's a specific deny rule, and
 * "default" if there is neither.  */
static enum oddjob_acl_sense
check_acl(struct oddjob_acl *acl, const char *user, unsigned long uid,
	  const char *selinux_context)
{
	struct oddjob_acl *i;
	/* Process ALL of the denial rules first. */
	for (i = acl; i != NULL; i = i->next) {
		if (i->sense == oddjob_acl_deny) {
			if (check_one_ac_match(i, user, uid, selinux_context)) {
				if (globals.debug) {
					fprintf(stderr, "Matched deny rule (");
					if (i->apply_user) {
						fprintf(stderr, " user=%s ",
							i->user);
					}
					if (i->apply_min_uid) {
						fprintf(stderr, " min_uid=%lu ",
							i->min_uid);
					}
					if (i->apply_max_uid) {
						fprintf(stderr, " max_uid=%lu ",
							i->max_uid);
					}
#ifdef SELINUX_ACLS
					if (i->apply_selinux_enforcing) {
						fprintf(stderr, " seenforcing=%s ",
							i->selinux_enforcing ?
							"yes" : "no");
					}
					if (i->apply_selinux_context) {
						fprintf(stderr, " secontext=%s ",
							i->selinux_context);
					}
					if (i->apply_selinux_user) {
						fprintf(stderr, " seuser=%s ",
							i->selinux_user);
					}
					if (i->apply_selinux_role) {
						fprintf(stderr, " serole=%s ",
							i->selinux_role);
					}
					if (i->apply_selinux_type) {
						fprintf(stderr, " setype=%s ",
							i->selinux_type);
					}
					if (i->apply_selinux_range) {
						fprintf(stderr, " serange=%s ",
							i->selinux_range);
					}
#endif
					fprintf(stderr, ")\n");
				}
				return oddjob_acl_deny;
			}
		}
	}
	/* Now process the allow rules as a group. */
	for (i = acl; i != NULL; i = i->next) {
		if (i->sense == oddjob_acl_allow) {
			if (check_one_ac_match(i, user, uid, selinux_context)) {
				if (globals.debug) {
					fprintf(stderr, "Matched allow rule (");
					if (i->apply_user) {
						fprintf(stderr, " user=%s ",
							i->user);
					}
					if (i->apply_min_uid) {
						fprintf(stderr, " min_uid=%lu ",
							i->min_uid);
					}
					if (i->apply_max_uid) {
						fprintf(stderr, " max_uid=%lu ",
							i->max_uid);
					}
#ifdef SELINUX_ACLS
					if (i->apply_selinux_enforcing) {
						fprintf(stderr, " enforcing=%s ",
							i->selinux_enforcing ?
							"yes" : "no");
					}
					if (i->apply_selinux_context) {
						fprintf(stderr, " context=%s ",
							i->selinux_context);
					}
					if (i->apply_selinux_user) {
						fprintf(stderr, " user=%s ",
							i->selinux_user);
					}
					if (i->apply_selinux_role) {
						fprintf(stderr, " role=%s ",
							i->selinux_role);
					}
					if (i->apply_selinux_type) {
						fprintf(stderr, " type=%s ",
							i->selinux_type);
					}
					if (i->apply_selinux_range) {
						fprintf(stderr, " range=%s ",
							i->selinux_range);
					}
#endif
					fprintf(stderr, ")\n");
				}
				return oddjob_acl_allow;
			}
		}
	}
	return oddjob_acl_default;
}

/* Check the ACL associated with a specific method for a particular client.  If
 * there is no match, proceed up to its containing interface, object, and
 * service, and lastly try the global ACL.  If, after all of that, there's no
 * match, return a failure code. */
static enum oddjob_acl_sense
check_method_acl(struct method *method, const char *user, unsigned long uid,
		 const char *selinux_context)
{
	struct oddjob_acl *acl;
	check_selinux_applicable();
	acl = method->acl;
	if (globals.debug) {
		fprintf(stderr, "Checking method ACL (%s:%s:%s:%s).\n",
			method->interface->object->service->name,
			method->interface->object->name,
			method->interface->name,
			method->name);
	}
	switch (check_acl(acl, user, uid, selinux_context)) {
	case oddjob_acl_allow:
		return oddjob_acl_allow;
	case oddjob_acl_deny:
		return oddjob_acl_deny;
	default:
		break;
	}
	if (globals.debug) {
		fprintf(stderr, "Checking interface ACL (%s:%s:%s).\n",
			method->interface->object->service->name,
			method->interface->object->name,
			method->interface->name);
	}
	acl = method->interface->acl;
	switch (check_acl(acl, user, uid, selinux_context)) {
	case oddjob_acl_allow:
		return oddjob_acl_allow;
	case oddjob_acl_deny:
		return oddjob_acl_deny;
	default:
		break;
	}
	if (globals.debug) {
		fprintf(stderr, "Checking object ACL (%s:%s).\n",
			method->interface->object->service->name,
			method->interface->object->name);
	}
	acl = method->interface->object->acl;
	switch (check_acl(acl, user, uid, selinux_context)) {
	case oddjob_acl_allow:
		return oddjob_acl_allow;
	case oddjob_acl_deny:
		return oddjob_acl_deny;
	default:
		break;
	}
	if (globals.debug) {
		fprintf(stderr, "Checking service ACL (%s).\n",
			method->interface->object->service->name);
	}
	acl = method->interface->object->service->acl;
	switch (check_acl(acl, user, uid, selinux_context)) {
	case oddjob_acl_allow:
		return oddjob_acl_allow;
	case oddjob_acl_deny:
		return oddjob_acl_deny;
	default:
		break;
	}
	if (globals.debug) {
		fprintf(stderr, "Checking global ACL.\n");
	}
	acl = method->interface->object->service->config->acl;
	switch (check_acl(acl, user, uid, selinux_context)) {
	case oddjob_acl_allow:
		return oddjob_acl_allow;
	default:
		if (globals.debug) {
			fprintf(stderr, "Fell through all ACLs.\n");
		}
		/* fall through */
	case oddjob_acl_deny:
		return oddjob_acl_deny;
		break;
	}
}

/* Check if we are in SELinux enforcing mode. */
static void
check_selinux_applicable(void)
{
#ifdef SELINUX_ACLS
	globals.selinux_enabled = (is_selinux_enabled() != 0);
	if (globals.selinux_enabled) {
		globals.selinux_enforcing = (security_getenforce() != 0);
	} else {
		globals.selinux_enforcing = FALSE;
	}
#endif
}

/* Convenience functions for reading attributes and contents of XML nodes. */
static dbus_bool_t
load_config_xml_node_name_is(xmlNodePtr node, const char *name)
{
	return (node->name != NULL) &&
	       (xmlStrcmp(node->name, (xmlChar*) name) == 0);
}
static dbus_bool_t
load_config_xml_attr_name_is(xmlAttrPtr attr, const char *name)
{
	return (attr->name != NULL) &&
	       (xmlStrcmp(attr->name, (xmlChar*) name) == 0);
}
static const char *
load_config_xml_attr_data(xmlAttrPtr attr)
{
	xmlNodePtr child;
	for (child = attr->children; child != NULL; child = child->next) {
		if ((child->type == XML_TEXT_NODE) &&
		    (child->content != NULL)) {
			return (const char *) child->content;
		}
	}
	return "";
}
static const char *
load_config_xml_node_data(xmlNodePtr node)
{
	xmlNodePtr child;
	for (child = node->children; child != NULL; child = child->next) {
		if ((child->type == XML_TEXT_NODE) &&
		    (child->content != NULL)) {
			return (const char *) child->content;
		}
	}
	return "";
}

/* Load an ACL entry from the configuration file. */
static dbus_bool_t
load_config_oddjobconfig_oddjob_access(xmlNodePtr cur,
				       struct oddjob_acl **acls,
				       enum oddjob_acl_sense sense)
{
	xmlAttrPtr attr;
	struct oddjob_acl *ac, *acl;
	const char *p;
	char *q;

	ac = oddjob_malloc(sizeof(*ac));
	if (ac == NULL) {
		fprintf(stderr, "Out of memory\n");
		return FALSE;
	}
	memset(ac, 0, sizeof(*ac));

	ac->sense = sense;
	if (globals.debug) {
		fprintf(stderr, "Add new %s%s rule ( ",
			sense == oddjob_acl_allow ? "allow" : "",
			sense == oddjob_acl_deny ? "deny" : "");
	}
	for (attr = cur->properties; attr != NULL; attr = attr->next) {
		if (load_config_xml_attr_name_is(attr, "user")) {
			ac->apply_user = TRUE;
			ac->user = oddjob_strdup(load_config_xml_attr_data(attr));
			if (globals.debug) {
				fprintf(stderr, "user=\"%s\" ", ac->user);
			}
		} else
		if (load_config_xml_attr_name_is(attr, "min_uid")) {
			p = load_config_xml_attr_data(attr);
			ac->min_uid = strtoul(p, &q, 0);
			if ((*p != '\0') && (q != NULL) && (*q == '\0')) {
				ac->apply_min_uid = TRUE;
				if (globals.debug) {
					fprintf(stderr, "min_uid=\"%lu\" ",
						ac->min_uid);
				}
			}
		} else
		if (load_config_xml_attr_name_is(attr, "max_uid")) {
			p = load_config_xml_attr_data(attr);
			ac->max_uid = strtoul(p, &q, 0);
			if ((*p != '\0') && (q != NULL) && (*q == '\0')) {
				ac->apply_max_uid = TRUE;
				if (globals.debug) {
					fprintf(stderr, "max_uid=\"%lu\" ",
						ac->max_uid);
				}
			}
#ifdef SELINUX_ACLS
		} else
		if (load_config_xml_attr_name_is(attr, "selinux_enforcing")) {
			const char *enforcing;
			ac->apply_selinux_enforcing = TRUE;
			ac->selinux_enforcing = TRUE;
			enforcing = load_config_xml_attr_data(attr);
			if (enforcing != NULL) {
				if (strcmp(enforcing, "no") == 0) {
					ac->selinux_enforcing = FALSE;
				} else
				if (strcmp(enforcing, "yes") == 0) {
					ac->selinux_enforcing = TRUE;
				} else {
					fprintf(stderr,
						"Invalid selinux_enforcing "
						"\"%s\" (expected \"yes\" or "
						"\"no\")!\n", enforcing);
					return FALSE;
				}
			}
			if (globals.debug) {
				fprintf(stderr, "selinux_enforcing=\"%s\" ",
					ac->selinux_enforcing ? "yes" : "no");
			}
		} else
		if (load_config_xml_attr_name_is(attr, "selinux_context")) {
			ac->apply_selinux_context = TRUE;
			ac->selinux_context = oddjob_strdup(load_config_xml_attr_data(attr));
			if (globals.debug) {
				fprintf(stderr, "selinux_context=\"%s\" ",
					ac->selinux_context);
			}
		} else
		if (load_config_xml_attr_name_is(attr, "selinux_user")) {
			ac->apply_selinux_user = TRUE;
			ac->selinux_user = oddjob_strdup(load_config_xml_attr_data(attr));
			if (globals.debug) {
				fprintf(stderr, "selinux_user=\"%s\" ",
					ac->selinux_user);
			}
		} else
		if (load_config_xml_attr_name_is(attr, "selinux_role")) {
			ac->apply_selinux_role = TRUE;
			ac->selinux_role = oddjob_strdup(load_config_xml_attr_data(attr));
			if (globals.debug) {
				fprintf(stderr, "selinux_role=\"%s\" ",
					ac->selinux_role);
			}
		} else
		if (load_config_xml_attr_name_is(attr, "selinux_type")) {
			ac->apply_selinux_type = TRUE;
			ac->selinux_type = oddjob_strdup(load_config_xml_attr_data(attr));
			if (globals.debug) {
				fprintf(stderr, "selinux_type=\"%s\" ",
					ac->selinux_type);
			}
		} else
		if (load_config_xml_attr_name_is(attr, "selinux_range")) {
			ac->apply_selinux_range = TRUE;
			ac->selinux_range = oddjob_strdup(load_config_xml_attr_data(attr));
			if (globals.debug) {
				fprintf(stderr, "selinux_range=\"%s\" ",
					ac->selinux_range);
			}
#endif
		} else {
			if (globals.debug) {
				fprintf(stderr, "unknown attribute \"%s\" in "
					"<%s%s> element\n", attr->name,
					(sense == oddjob_acl_allow) ?
					"allow" : "",
					(sense == oddjob_acl_deny) ?
					"deny" : "");
				return FALSE;
			}
		}
	}
	if (globals.debug) {
		fprintf(stderr, ").\n");
	}

	if (*acls != NULL) {
		/* Append this AC to the list. */
		acl = *acls;
		while (acl->next != NULL) {
			acl = acl->next;
		}
		acl->next = ac;
	} else {
		/* Make this AC the list. */
		*acls = ac;
	}

	return TRUE;
}

/* Load the configuration file specified in an <include> node. */
static dbus_bool_t
load_config_oddjobconfig_include(struct oddjob_config *config, xmlNodePtr cur)
{
	xmlAttrPtr attr;
	dbus_bool_t ignore_missing, okay;
	glob_t globbed;
	unsigned int i;

	ignore_missing = FALSE;
	if (globals.debug) {
		fprintf(stderr, "Include(");
	}
	/* Check if we need to ignore missing or mismatch files. */
	for (attr = cur->properties; attr != NULL; attr = attr->next) {
		if (load_config_xml_attr_name_is(attr, "ignore_missing")) {
			if (globals.debug) {
				fprintf(stderr, "ignore_missing=\"%s\",",
					load_config_xml_attr_data(attr));
			}
			if (strcmp(load_config_xml_attr_data(attr),
				   "yes") == 0) {
				ignore_missing = TRUE;
			}
		} else {
			if (globals.debug) {
				fprintf(stderr, "unknown attribute \"%s\" in "
					"<include> element\n", attr->name);
				return FALSE;
			}
		}
	}
	if (globals.debug) {
		fprintf(stderr, "\"%s\").\n", load_config_xml_node_data(cur));
	}

	/* Glob for the filename to allow wildcards to work. */
	memset(&globbed, 0, sizeof(globbed));
	if (glob(load_config_xml_node_data(cur), GLOB_NOCHECK,
		 NULL, &globbed) != 0) {
		if (globals.debug) {
			fprintf(stderr, "glob: %s: %s.\n",
				load_config_xml_node_data(cur),
				strerror(errno));
		}
		return FALSE;
	}

	/* Load each one, but only return success if all succeed. */
	for (i = 0, okay = TRUE; i < globbed.gl_pathc; i++) {
		okay = load_config(config,
				   globbed.gl_pathv[i],
				   ignore_missing) && okay;
	}

	globfree(&globbed);

	return okay;
}

/* Load a <helper> element of a <method> and initialize its fields. */
static dbus_bool_t
load_config_oddjobconfig_oddjob_helper(xmlNodePtr cur,
				       struct method *method)
{
	xmlAttrPtr attr;
	int n_arguments;
	const char *execpath, *arguments, *prepend, *arg_method, *parse_error;
	char *p, **argv;
	dbus_bool_t prepend_user;
	enum oddjob_argument_passing_method arg_passing_method;
	/* Sanity check -- don't let people define helpers for internal
	 * methods. */
	if (method->type != method_invalid) {
		switch (method->type) {
		case method_internal:
			fprintf(stderr, "Error, <helper> node not allowed "
				"within a <method> describing an internal "
				"method.\n");
			break;
		case method_external:
			fprintf(stderr, "Error, duplicate <helper> node.\n");
			break;
		case method_invalid:
			/* fall through */
		default:
			break;
		}
		return FALSE;
	}
	/* Pull out the attributes. */
	execpath = NULL;
	arguments = NULL;
	prepend = NULL;
	arg_method = NULL;
	arg_passing_method = oddjob_argument_passing_stdin;
	for (attr = cur->properties; attr != NULL; attr = attr->next) {
		if (load_config_xml_attr_name_is(attr, "exec")) {
			execpath = load_config_xml_attr_data(attr);
		} else
		if (load_config_xml_attr_name_is(attr, "arguments")) {
			arguments = load_config_xml_attr_data(attr);
		} else
		if (load_config_xml_attr_name_is(attr, "prepend_user_name")) {
			prepend = load_config_xml_attr_data(attr);
		} else
		if (load_config_xml_attr_name_is(attr,
						 "argument_passing_method")) {
			arg_method = load_config_xml_attr_data(attr);
		} else {
			if (globals.debug) {
				fprintf(stderr, "unknown attribute \"%s\" in "
					"<helper> element\n", attr->name);
				return FALSE;
			}
		}
	}
	/* Sanity check them as best we can. */
	if (execpath == NULL) {
		fprintf(stderr, "Required attribute \"exec\" not given!\n");
		return FALSE;
	}
	parse_error = NULL;
	argv = oddjob_parse_args(execpath, &parse_error);
	if (argv == NULL) {
		fprintf(stderr, "Error parsing command \"%s\": %s\n",
			execpath, parse_error ? parse_error : "Unknown error");
		return FALSE;
	}
	if (argv[0][0] != '/') {
		fprintf(stderr, "\"exec\" value \"%s\" is not "
			"an absolute path!\n", argv[0]);
		return FALSE;
	}
	n_arguments = 0;
	if (arguments != NULL) {
		n_arguments = strtol(arguments, &p, 0);
		if ((*arguments == '\0') || (p == NULL) || (*p != '\0')) {
			fprintf(stderr, "Invalid argument count \"%s\"!\n",
				arguments);
			return FALSE;
		}
	}
	prepend_user = FALSE;
	if (prepend != NULL) {
		if (strcmp(prepend, "yes") == 0) {
			prepend_user = TRUE;
		} else
		if (strcmp(prepend, "no") == 0) {
			prepend_user = FALSE;
		} else {
			fprintf(stderr, "Invalid prepend_user_name "
				"\"%s\" (expected \"yes\" or \"no\")!\n",
				arg_method);
			return FALSE;
		}
	}
	arg_passing_method = oddjob_argument_passing_stdin;
	if (arg_method != NULL) {
		if (strcmp(arg_method, "stdin") == 0) {
			arg_passing_method = oddjob_argument_passing_stdin;
		} else
		if (strcmp(arg_method, "cmdline") == 0) {
			arg_passing_method = oddjob_argument_passing_cmdline;
		} else {
			fprintf(stderr, "Invalid argument_passing_method "
				"\"%s\" (expected \"stdin\" or \"cmdline\")!\n",
				arg_method);
			return FALSE;
		}
	}
	method->type = method_external;
	method->n_arguments = n_arguments;
	method->argv = argv;
	method->handler = oddjobd_exec_method;
	method->prepend_user = prepend_user;
	method->argument_passing_method = arg_passing_method;
	return TRUE;
}

/* Add a method with the specified name to the list maintained in the specified
 * interface structure.  Leave its owner pointer unset, because it may yet be
 * moved.  Also assume that the named method isn't already in the list. */
static struct method *
method_add(struct interface *interface, const char *name)
{
	struct method *method;
	oddjob_resize_array((void **) &interface->methods,
			    sizeof(interface->methods[0]),
			    interface->n_methods,
			    interface->n_methods + 1);
	method = &interface->methods[interface->n_methods];
	method->name = oddjob_strdup(name);
	method->acl = NULL;
	method->type = method_invalid;
	method->n_arguments = 0;
	method->handler = NULL;
	method->argv = NULL;
	method->prepend_user = FALSE;
	method->argument_passing_method = oddjob_argument_passing_invalid;
	interface->n_methods++;
	return method;
}

/* Handle a <method> element. */
static dbus_bool_t
load_config_oddjobconfig_method(xmlNodePtr cur,
				struct interface *interface)
{
	xmlAttrPtr attr;
	xmlNodePtr child;
	const char *name;
	dbus_bool_t parsed;
	struct method *method;
	int i;

	/* Require a "name" attribute. */
	name = NULL;
	for (attr = cur->properties; attr != NULL; attr = attr->next) {
		if (load_config_xml_attr_name_is(attr, "name")) {
			name = load_config_xml_attr_data(attr);
		} else {
			if (globals.debug) {
				fprintf(stderr, "unknown attribute \"%s\" in "
					"<method> element\n", attr->name);
				return FALSE;
			}
		}
	}
	if (name == NULL) {
		fprintf(stderr, "<method> node in \"%s\" interface of \"%s\" "
			"object has no \"name\" attribute!\n",
			interface->name, interface->object->name);
		return FALSE;
	}
	/* Find the method. */
	for (i = 0; i < interface->n_methods; i++) {
		method = &interface->methods[i];
		if (strcmp(method->name, name) == 0) {
			break;
		}
	}
	/* If the method doesn't exist, create it. */
	if (i >= interface->n_methods) {
		method = method_add(interface, name);
	}
	/* Parse child nodes. */
	parsed = TRUE;
	for (child = cur->children; child != NULL; child = child->next) {
		if (load_config_xml_node_name_is(child, "helper")) {
			parsed = load_config_oddjobconfig_oddjob_helper(child,
								        method) &&
				 parsed;
		} else
		if (load_config_xml_node_name_is(child, "deny")) {
			load_config_oddjobconfig_oddjob_access(child,
							       &method->acl,
							       oddjob_acl_deny);
		} else
		if (load_config_xml_node_name_is(child, "allow")) {
			load_config_oddjobconfig_oddjob_access(child,
							       &method->acl,
							       oddjob_acl_allow);
		} else
		if (load_config_xml_node_name_is(child, "text")) {
			/* nothing */
		} else
		if (load_config_xml_node_name_is(child, "comment")) {
			/* nothing */
		} else {
			if (globals.debug) {
				fprintf(stderr, "unknown element \"%s\" within "
					"<method> element\n", child->name);
				return FALSE;
			}
		}
	}

	return parsed;
}

/* Create a new interface in the list maintained for the object.  Assume that
 * one doesn't already exist, and leave the owner pointer unset. */
static struct interface *
interface_add(struct object *object, const char *name)
{
	struct interface *interface;
	oddjob_resize_array((void **) &object->interfaces,
			    sizeof(object->interfaces[0]),
			    object->n_interfaces,
			    object->n_interfaces + 1);
	interface = &object->interfaces[object->n_interfaces];
	interface->name = oddjob_strdup(name);
	interface->methods = NULL;
	interface->n_methods = 0;
	interface->acl = NULL;
	object->n_interfaces++;
	return interface;
}

/* Handle an <interface> tag. */
static dbus_bool_t
load_config_oddjobconfig_interface(xmlNodePtr cur, struct object *object)
{
	xmlAttrPtr attr;
	xmlNodePtr child;
	const char *name;
	struct interface *interface;
	int i;
	dbus_bool_t parsed = TRUE;

	/* Require a "name" attribute. */
	name = NULL;
	for (attr = cur->properties; attr != NULL; attr = attr->next) {
		if (load_config_xml_attr_name_is(attr, "name")) {
			name = load_config_xml_attr_data(attr);
		} else {
			if (globals.debug) {
				fprintf(stderr, "unknown attribute \"%s\" in "
					"<interface> element\n", attr->name);
				return FALSE;
			}
		}
	}
	if (name == NULL) {
		fprintf(stderr, "<interface> node in object \"%s\" has no "
			"\"name\" attribute!\n", object->name);
		return FALSE;
	}
	/* Search for the interface. */
	for (i = 0; i < object->n_interfaces; i++) {
		interface = &object->interfaces[i];
		if (strcmp(interface->name, name) == 0) {
			break;
		}
	}
	/* Create the interface if it doesn't already exist. */
	if (i >= object->n_interfaces) {
		interface = interface_add(object, name);
	}
	/* Parse the child nodes. */
	for (child = cur->children; child != NULL; child = child->next) {
		if (load_config_xml_node_name_is(child, "method")) {
			parsed = load_config_oddjobconfig_method(child,
								 interface) &&
				 parsed;
		} else
		if (load_config_xml_node_name_is(child, "allow")) {
			load_config_oddjobconfig_oddjob_access(child,
							       &interface->acl,
							       oddjob_acl_allow);
		} else
		if (load_config_xml_node_name_is(child, "deny")) {
			load_config_oddjobconfig_oddjob_access(child,
							       &interface->acl,
							       oddjob_acl_deny);
		} else
		if (load_config_xml_node_name_is(child, "text")) {
			/* nothing */
		} else
		if (load_config_xml_node_name_is(child, "comment")) {
			/* nothing */
		} else {
			if (globals.debug) {
				fprintf(stderr, "unknown element \"%s\" within "
					"<interface> element\n", child->name);
				return FALSE;
			}
		}
	}

	return parsed;
}

/* Add an object to the service, assuming such an object doesn't already exist,
 * and leave its owner pointer blank as well. */
static struct object *
object_add(struct service *service, const char *name)
{
	struct object *object;
	oddjob_resize_array((void **) &service->objects,
			    sizeof(service->objects[0]),
			    service->n_objects,
			    service->n_objects + 1);
	object = &service->objects[service->n_objects];
	object->name = oddjob_strdup(name);
	object->interfaces = NULL;
	object->n_interfaces = 0;
	object->acl = NULL;
	service->n_objects++;
	return object;
}

/* Handle an <object> element. */
static dbus_bool_t
load_config_oddjobconfig_object(xmlNodePtr cur, struct service *service)
{
	xmlAttrPtr attr;
	xmlNodePtr child;
	const char *name;
	struct object *object;
	int i;
	dbus_bool_t parsed = TRUE;

	/* Require a "name" attribute. */
	name = NULL;
	for (attr = cur->properties; attr != NULL; attr = attr->next) {
		if (load_config_xml_attr_name_is(attr, "name")) {
			name = load_config_xml_attr_data(attr);
		} else {
			if (globals.debug) {
				fprintf(stderr, "unknown attribute \"%s\" in "
					"<object> element\n", attr->name);
				return FALSE;
			}
		}
	}
	if (name == NULL) {
		fprintf(stderr, "<object> node has no \"name\" "
			"attribute!\n");
		return FALSE;
	}
	/* Search for the object. */
	for (i = 0; i < service->n_objects; i++) {
		object = &service->objects[i];
		if (strcmp(object->name, name) == 0) {
			break;
		}
	}
	/* Create the object node if it doesn't already exist. */
	if (i >= service->n_objects) {
		object = object_add(service, name);
	}
	/* Parse the child nodes. */
	for (child = cur->children; child != NULL; child = child->next) {
		if (load_config_xml_node_name_is(child, "interface")) {
			parsed = load_config_oddjobconfig_interface(child,
								    object) &&
				 parsed;
		} else
		if (load_config_xml_node_name_is(child, "allow")) {
			load_config_oddjobconfig_oddjob_access(child,
							       &object->acl,
							       oddjob_acl_allow);
		} else
		if (load_config_xml_node_name_is(child, "deny")) {
			load_config_oddjobconfig_oddjob_access(child,
							       &object->acl,
							       oddjob_acl_deny);
		} else
		if (load_config_xml_node_name_is(child, "text")) {
			/* nothing */
		} else
		if (load_config_xml_node_name_is(child, "comment")) {
			/* nothing */
		} else {
			if (globals.debug) {
				fprintf(stderr, "unknown element \"%s\" within "
					"<object> element\n", child->name);
				return FALSE;
			}
		}
	}

	return parsed;
}

/* Add a service to the global service list, assuming that there isn't already
 * one there, that is. */
static struct service *
service_add(struct oddjob_config *config, const char *name)
{
	struct service *service;
	oddjob_resize_array((void **) &config->services,
			    sizeof(config->services[0]),
			    config->n_services,
			    config->n_services + 1);
	service = &config->services[config->n_services];
	service->name = oddjob_strdup(name);
	service->config = config;
	service->objects = NULL;
	service->n_objects = 0;
	service->acl = NULL;
	config->n_services++;
	return service;
}

/* Handle a <service> node. */
static dbus_bool_t
load_config_oddjobconfig_service(struct oddjob_config *config, xmlNodePtr cur)
{
	xmlNodePtr child;
	xmlAttrPtr attr;
	dbus_bool_t parsed;
	parsed = TRUE;
	const char *name;
	struct service *service;
	int i;

	/* Require a "name" attribute. */
	name = NULL;
	for (attr = cur->properties; attr != NULL; attr = attr->next) {
		if (load_config_xml_attr_name_is(attr, "name")) {
			name = load_config_xml_attr_data(attr);
		} else {
			if (globals.debug) {
				fprintf(stderr, "unknown attribute \"%s\" in "
					"<service> element\n", attr->name);
				return FALSE;
			}
		}
	}
	if (name == NULL) {
		fprintf(stderr, "<service> node has no \"name\" "
			"attribute!\n");
		return FALSE;
	}
	/* Look for the service node. */
	for (i = 0; i < config->n_services; i++) {
		service = &config->services[i];
		if (strcmp(service->name, name) == 0) {
			break;
		}
	}
	/* Create the service node if it doesn't already exist. */
	if (i >= config->n_services) {
		service = service_add(config, name);
	}
	/* Parse the child nodes. */
	for (child = cur->children; child != NULL; child = child->next) {
		if (load_config_xml_node_name_is(child, "object")) {
			parsed = load_config_oddjobconfig_object(child,
								 service) &&
				 parsed;
		} else
		if (load_config_xml_node_name_is(child, "allow")) {
			load_config_oddjobconfig_oddjob_access(child,
							       &service->acl,
							       oddjob_acl_allow);
		} else
		if (load_config_xml_node_name_is(child, "deny")) {
			load_config_oddjobconfig_oddjob_access(child,
							       &service->acl,
							       oddjob_acl_deny);
		} else
		if (load_config_xml_node_name_is(child, "text")) {
			/* nothing */
		} else
		if (load_config_xml_node_name_is(child, "comment")) {
			/* nothing */
		} else {
			if (globals.debug) {
				fprintf(stderr, "unknown element \"%s\" within "
					"<service> element\n", child->name);
				return FALSE;
			}
		}
	}
	return parsed;
}

/* Handle a <oddjobconfig> node. */
static dbus_bool_t
load_config_oddjobconfig(struct oddjob_config *config, xmlNodePtr cur)
{
	xmlNodePtr child;
	dbus_bool_t parsed;
	parsed = TRUE;
	for (child = cur->children; child != NULL; child = child->next) {
		if (load_config_xml_node_name_is(child, "include")) {
			parsed = load_config_oddjobconfig_include(config,
								  child) &&
				 parsed;
		} else
		if (load_config_xml_node_name_is(child, "service")) {
			parsed = load_config_oddjobconfig_service(config,
								  child) &&
				 parsed;
		} else
		if (load_config_xml_node_name_is(child, "allow")) {
			load_config_oddjobconfig_oddjob_access(child,
							       &config->acl,
							       oddjob_acl_allow);
		} else
		if (load_config_xml_node_name_is(child, "deny")) {
			load_config_oddjobconfig_oddjob_access(child,
							       &config->acl,
							       oddjob_acl_deny);
		} else
		if (load_config_xml_node_name_is(child, "text")) {
			/* nothing */
		} else
		if (load_config_xml_node_name_is(child, "comment")) {
			/* nothing */
		} else {
			if (globals.debug) {
				fprintf(stderr, "unknown element \"%s\" within "
					"<oddjobconfig> element\n",
					child->name);
				return FALSE;
			}
		}
	}
	return parsed;
}

/* Load the contents of a configuration file. */
static dbus_bool_t
load_config(struct oddjob_config *config,
	    const char *filename, dbus_bool_t ignore_missing)
{
	xmlDocPtr doc;
	xmlNodePtr cur;
	struct stat st;
	dbus_bool_t parsed;

	if (filename == NULL) {
		filename = SYSCONFDIR "/" PACKAGE "d.conf";
	}

	if (ignore_missing &&
	    (stat(filename, &st) == -1) && (errno == ENOENT)) {
		if (globals.debug) {
			fprintf(stderr, "Ignoring missing file \"%s\".\n",
				filename);
		}
		return TRUE;
	}

	if (globals.debug) {
		fprintf(stderr, "Parsing configuration file \"%s\".\n",
			filename);
	}

	xmlInitGlobals();
	doc = xmlParseFile(filename);
	if (doc == NULL) {
		fprintf(stderr, "Error parsing configuration from \"%s\".\n",
			filename);
		return FALSE;
	}

	parsed = FALSE;
	cur = xmlDocGetRootElement(doc);
	if (cur != NULL) {
		if (load_config_xml_node_name_is(cur, "oddjobconfig")) {
			parsed = load_config_oddjobconfig(config, cur);
		} else {
			if (globals.debug) {
				fprintf(stderr, "unknown root element \"%s\" ",
					cur->name);
				return FALSE;
			}
		}
	}

	xmlFreeDoc(doc);
	xmlCleanupGlobals();

	return parsed;
}

static void
free_acl(struct oddjob_acl *acl)
{
	struct oddjob_acl *tofree;
	while (acl != NULL) {
		tofree = acl;
		acl = acl->next;
#ifdef SELINUX_ACLS
		oddjob_free(tofree->selinux_context);
		oddjob_free(tofree->selinux_user);
		oddjob_free(tofree->selinux_role);
		oddjob_free(tofree->selinux_type);
#endif
		oddjob_free(tofree->user);
		oddjob_free(tofree);
	}
}

static void
unload_config(struct oddjob_config *config)
{
	struct service *service;
	struct object *object;
	struct interface *interface;
	struct method *method;
	int i, j, k, l;

	free_acl(config->acl);
	config->acl = NULL;
	for (i = 0; i < config->n_services; i++) {
		service = &config->services[i];
		oddjob_free(service->name);
		service->name = NULL;
		service->config = NULL;
		free_acl(service->acl);
		service->acl = NULL;
		for (j = 0; j < service->n_objects; j++) {
			object = &service->objects[j];
			oddjob_free(object->name);
			object->name = NULL;
			object->service = NULL;
			free_acl(object->acl);
			object->acl = NULL;
			for (k = 0; k < object->n_interfaces; k++) {
				interface = &object->interfaces[k];
				oddjob_free(interface->name);
				interface->name = NULL;
				interface->object = NULL;
				free_acl(interface->acl);
				interface->acl = NULL;
				for (l = 0; l < interface->n_methods; l++) {
					method = &interface->methods[l];
					oddjob_free(method->name);
					method->name = NULL;
					method->interface = NULL;
					free_acl(method->acl);
					method->acl = NULL;
					oddjob_free_args(method->argv);
					method->argv = NULL;
				}
				oddjob_free(interface->methods);
				interface->methods = NULL;
				interface->n_methods = 0;
			}
			oddjob_free(object->interfaces);
			object->interfaces = NULL;
			object->n_interfaces = 0;
		}
		oddjob_free(service->objects);
		service->objects = NULL;
		service->n_objects = 0;
	}
	oddjob_free(config->services);
	config->n_services = 0;
	oddjob_free(config);
}

/* Callback for mainloop waitpid() checks. */
static void
oddjob_pid_service(pid_t pid, int status, void *data)
{
	struct oddjob_async_task *task;
	char outbuf[LINE_MAX];

	task = data;

	/* If the child exited on a signal, return an error. */
	if (WIFSIGNALED(status)) {
		snprintf(outbuf, sizeof(outbuf),
			 "Child exited on signal %d.",
			 WTERMSIG(status));
		if (globals.debug) {
			fprintf(stderr, "%s\n", outbuf);
		}
		oddjob_dbus_send_message_response_error(task->msg,
							ODDJOB_ERROR_EXEC,
							outbuf);
	}

	/* If the child exited normally, even in error, return the result. */
	if (WIFEXITED(status)) {
		if (globals.debug) {
			fprintf(stderr, "Child completed its task "
				"(status=%d, %ld bytes on stdout, "
				"%ld on stderr).\n", WEXITSTATUS(status),
				(long)oddjob_buffer_length(task->stdout_buffer),
				(long)oddjob_buffer_length(task->stderr_buffer));
		}
		oddjob_dbus_send_message_response_success(task->msg,
							  WEXITSTATUS(status),
							  task->stdout_buffer,
							  task->stderr_buffer,
							  FALSE);
	}
	/* Free the task. */
	task->pid = -1;
	oddjob_buffer_free(task->stdin_buffer);
	oddjob_buffer_free(task->stdout_buffer);
	oddjob_buffer_free(task->stderr_buffer);
	oddjob_dbus_message_free(task->msg);
	oddjob_free(task->service);
	oddjob_free(task->path);
	oddjob_free(task->interface);
	oddjob_free(task->method);
	oddjob_free(task->calling_user);
	oddjob_free(task->argv);
	oddjob_free(task);
}

/* Handle descriptor-ready status. */
static dbus_bool_t
oddjob_watch_service(int fd, DBusWatchFlags flags, void *data)
{
	struct oddjob_async_task *task;
	dbus_bool_t stop_watching;
	int i, *fdp, invalid_fd;
	struct oddjob_buffer *manip_buffer;
	char buf[LINE_MAX];

	task = data;
	stop_watching = FALSE;
	invalid_fd = -1;
	fdp = &invalid_fd;
	manip_buffer = NULL;

	/* Reduce the fd to a buffer and a pointer to its fd. */
	if (fd == task->stdin_fd) {
		fdp = &task->stdin_fd;
		manip_buffer = task->stdin_buffer;
	}
	if ((fd == task->stdout_fd) || (fd == task->stderr_fd)) {
		if (fd == task->stdout_fd) {
			fdp = &task->stdout_fd;
			manip_buffer = task->stdout_buffer;
		} else {
			fdp = &task->stderr_fd;
			manip_buffer = task->stderr_buffer;
		}
	}
	/* Based on the flags, do I/O and buffer management. */
	if (flags & DBUS_WATCH_READABLE) {
		i = read(*fdp, buf, sizeof(buf));
		switch (i) {
		case -1:
		case 0:
			close(*fdp);
			*fdp = -1;
			stop_watching = TRUE;
			break;
		default:
			oddjob_buffer_append(manip_buffer,
					     (const unsigned char *)buf,
					     i);
			break;
		}
	}
	if (flags & DBUS_WATCH_WRITABLE) {
		if (oddjob_buffer_length(manip_buffer) == 0) {
			close(*fdp);
			*fdp = -1;
			stop_watching = TRUE;
		} else {
			i = write(*fdp,
				  oddjob_buffer_data(manip_buffer),
				  oddjob_buffer_length(manip_buffer));
			switch (i) {
			case -1:
				close(*fdp);
				*fdp = -1;
				stop_watching = TRUE;
				break;
			default:
				oddjob_buffer_consume(manip_buffer, i);
				if (oddjob_buffer_length(manip_buffer) == 0) {
					close(*fdp);
					*fdp = -1;
					stop_watching = TRUE;
				}
				break;
			}
		}
	}
	if (flags & DBUS_WATCH_ERROR) {
		close(*fdp);
		*fdp = -1;
		stop_watching = TRUE;
	}
	/* If we're done, then add this task to the PID watch list. */
	if ((task->stdin_fd == -1) &&
	    (task->stdout_fd == -1) &&
	    (task->stderr_fd == -1)) {
		mainloop_pid_add(task->pid, oddjob_pid_service, data);
	}
	return stop_watching;
}

/* Run an external helper. */
static void
oddjobd_exec_method(struct oddjob_dbus_context *ctx,
		    struct oddjob_dbus_message *msg,
		    const char *service_name,
		    const char *object_path,
		    const char *interface_name,
		    const char *method_name,
		    const char *user,
		    unsigned long uid,
		    void *data)
{
	struct method *method;
	int exec_status[2], child_in[2], child_out[2], child_err[2], null[3], i;
	unsigned int n;
	unsigned char exec_errno;
	char buf[PATH_MAX];
	int status;
	const char *arg;
	struct oddjob_async_task *task;

	method = data;

	if (globals.debug) {
		fprintf(stderr,
			"Received request for \"%s:%s:%s:%s\" from %s.\n",
			service_name, object_path, interface_name, method_name,
			user);
	}
	if (check_method_acl(method, user, uid,
			     oddjob_dbus_message_get_selinux_context(msg)) !=
	    oddjob_acl_allow) {
		if (globals.debug) {
			fprintf(stderr, "Request for \"%s\" denied to %s.\n",
				method->name, user);
		}
		oddjob_dbus_send_message_response_error(msg,
							ODDJOB_ERROR_ACL,
							"ACL does not allow access");
		return;
	}

	/* Open /dev/null three times, just in case stdio aren't already set. */
	if (globals.debug) {
		fprintf(stderr, "Opening /dev/null 3 times.\n");
	}
	for (n = 0; n < sizeof(null) / sizeof(null[0]); n++) {
		null[n] = open("/dev/null", O_RDWR);
		if (null[n] == -1) {
			snprintf(buf, sizeof(buf),
				 "Error at open(/dev/null) %d: %s.",
				 n + 1, strerror(errno));
			if (globals.debug) {
				fprintf(stderr, "%s\n", buf);
			}
			oddjob_dbus_send_message_response_error(msg,
								ODDJOB_ERROR_INTERNAL,
								buf);
			/* Clean up any /dev/null descriptors which we've
			 * already opened. */
			i = n - 1;
			while (i >= 0) {
				close(null[i]);
				i--;
			}
			return;
		}
	}
	/* Create a pipe for returning the exec() failure code. */
	if (pipe(exec_status) == -1) {
		close(null[0]);
		close(null[1]);
		close(null[2]);
		snprintf(buf, sizeof(buf),
			 "Error at pipe(1): %s.", strerror(errno));
		if (globals.debug) {
			fprintf(stderr, "%s\n", buf);
		}
		oddjob_dbus_send_message_response_error(msg,
							ODDJOB_ERROR_INTERNAL,
							buf);
		return;
	}
	/* Create a trio of pipes for stdio. */
	if (pipe(child_in) == -1) {
		close(exec_status[0]);
		close(exec_status[1]);
		close(null[0]);
		close(null[1]);
		close(null[2]);
		snprintf(buf, sizeof(buf),
			 "Error at pipe(2): %s.", strerror(errno));
		if (globals.debug) {
			fprintf(stderr, "%s\n", buf);
		}
		oddjob_dbus_send_message_response_error(msg,
							ODDJOB_ERROR_INTERNAL,
							buf);
		return;
	}
	if (pipe(child_out) == -1) {
		close(child_in[0]);
		close(child_in[1]);
		close(exec_status[0]);
		close(exec_status[1]);
		close(null[0]);
		close(null[1]);
		close(null[2]);
		snprintf(buf, sizeof(buf),
			 "Error at pipe(3): %s.", strerror(errno));
		if (globals.debug) {
			fprintf(stderr, "%s\n", buf);
		}
		oddjob_dbus_send_message_response_error(msg,
							ODDJOB_ERROR_INTERNAL,
							buf);
		return;
	}
	if (pipe(child_err) == -1) {
		close(child_out[0]);
		close(child_out[1]);
		close(child_in[0]);
		close(child_in[1]);
		close(exec_status[0]);
		close(exec_status[1]);
		close(null[0]);
		close(null[1]);
		close(null[2]);
		snprintf(buf, sizeof(buf),
			 "Error at pipe(4): %s.", strerror(errno));
		if (globals.debug) {
			fprintf(stderr, "%s\n", buf);
		}
		oddjob_dbus_send_message_response_error(msg,
							ODDJOB_ERROR_INTERNAL,
							buf);
		return;
	}
	if ((fcntl(child_out[0], F_SETFL, O_NONBLOCK) == -1) ||
	    (fcntl(child_err[0], F_SETFL, O_NONBLOCK) == -1)) {
		close(child_err[0]);
		close(child_err[1]);
		close(child_out[0]);
		close(child_out[1]);
		close(child_in[0]);
		close(child_in[1]);
		close(exec_status[0]);
		close(exec_status[1]);
		close(null[0]);
		close(null[1]);
		close(null[2]);
		snprintf(buf, sizeof(buf),
			 "Error at fcntl(): %s.", strerror(errno));
		if (globals.debug) {
			fprintf(stderr, "%s\n", buf);
		}
		oddjob_dbus_send_message_response_error(msg,
							ODDJOB_ERROR_INTERNAL,
							buf);
		return;
	}
	/* At this point we *know* that none of pipes are on stdio, so we no
	 * longer need null[]. */
	close(null[0]);
	close(null[1]);
	close(null[2]);
	/* Here's where the heavy lifting starts.  Do all of the memory
	 * allocation which might fail in the child. */
	task = malloc(sizeof(struct oddjob_async_task));
	if (task == NULL) {
		close(child_err[0]);
		close(child_err[1]);
		close(child_out[0]);
		close(child_out[1]);
		close(child_in[0]);
		close(child_in[1]);
		close(exec_status[0]);
		close(exec_status[1]);
		snprintf(buf, sizeof(buf),
			 "Out of memory: %s.", strerror(errno));
		if (globals.debug) {
			fprintf(stderr, "%s\n", buf);
		}
		oddjob_dbus_send_message_response_error(msg,
							ODDJOB_ERROR_INTERNAL,
							buf);
		return;
	}
	/* Allocate space for a copy of the calling message, the child's
	 * arguments, our environment variables, and I/O buffers. */
	task->msg = oddjob_dbus_message_dup(msg);
	task->stdin_buffer = oddjob_buffer_new(LINE_MAX);
	task->stdout_buffer = oddjob_buffer_new(LINE_MAX);
	task->stderr_buffer = oddjob_buffer_new(LINE_MAX);
	switch (method->argument_passing_method) {
	case oddjob_argument_passing_cmdline:
		for (i = 1; method->argv[i] != NULL; i++) {
			continue;
		}
		n = (i + 3 + oddjob_dbus_message_get_n_args(msg)) *
		    sizeof(char *);
		task->argv = oddjob_malloc0(n);
		n = 0;
		if (strchr(method->argv[0], '/') != NULL) {
			task->argv[n++] = strrchr(method->argv[0], '/') + 1;
		} else {
			task->argv[n++] = method->argv[0];
		}
		if (method->prepend_user) {
			task->argv[n++] = (char *) user;
		}
		for (i = 1; method->argv[i] != NULL; i++) {
			arg = method->argv[i];
			task->argv[n++] = (char *) arg;
		}
		for (i = 0; i < method->n_arguments; i++) {
			arg = oddjob_dbus_message_get_arg(msg, i);
			task->argv[n++] = (char *) arg;
		}
		break;
	case oddjob_argument_passing_stdin:
		for (i = 1; method->argv[i] != NULL; i++) {
			continue;
		}
		n = (i + 3) * sizeof(char *);
		task->argv = oddjob_malloc0(n);
		n = 0;
		if (strchr(method->argv[0], '/') != NULL) {
			task->argv[n++] = strrchr(method->argv[0], '/') + 1;
		} else {
			task->argv[n++] = method->argv[0];
		}
		for (i = 1; method->argv[i] != NULL; i++) {
			arg = method->argv[i];
			task->argv[n++] = (char *) arg;
		}
		if (method->prepend_user) {
			oddjob_buffer_append(task->stdin_buffer,
					     (const unsigned char *) user, -1);
			oddjob_buffer_append(task->stdin_buffer,
					     (const unsigned char *) "\n", 1);
		}
		for (i = 0; i < method->n_arguments; i++) {
			arg = oddjob_dbus_message_get_arg(msg, i);
			oddjob_buffer_append(task->stdin_buffer,
					     (const unsigned char *) arg, -1);
			oddjob_buffer_append(task->stdin_buffer,
					     (const unsigned char *) "\n", 1);
		}
		break;
	case oddjob_argument_passing_invalid:
		break;
	}
	task->service = oddjob_strdup_printf("%s=%s",
					     ODDJOB_SERVICE_ENV_VAR,
					     service_name);
	task->path = oddjob_strdup_printf("%s=%s",
					  ODDJOB_OBJECT_ENV_VAR, object_path);
	task->interface = oddjob_strdup_printf("%s=%s",
					       ODDJOB_INTERFACE_ENV_VAR,
					       interface_name);
	task->method = oddjob_strdup_printf("%s=%s",
					    ODDJOB_METHOD_ENV_VAR,
					    method_name);
	task->calling_user = oddjob_strdup_printf("%s=%s",
						  ODDJOB_CALLING_USER_VAR,
						  user);
	/* Make a note of which descriptors matter. */
	task->stdin_fd = child_in[1];
	task->stdout_fd = child_out[0];
	task->stderr_fd = child_err[0];
	/* All of that done, we can actually start a child. */
	task->pid = fork();
	switch (task->pid) {
	case -1:
		close(exec_status[0]);
		close(exec_status[1]);
		close(child_in[0]);
		close(child_in[1]);
		close(child_out[0]);
		close(child_out[1]);
		close(child_err[0]);
		close(child_err[1]);
		oddjob_buffer_free(task->stdin_buffer);
		oddjob_buffer_free(task->stdout_buffer);
		oddjob_buffer_free(task->stderr_buffer);
		oddjob_dbus_message_free(task->msg);
		oddjob_free(task->argv);
		oddjob_free(task->service);
		oddjob_free(task->path);
		oddjob_free(task->interface);
		oddjob_free(task->method);
		oddjob_free(task->calling_user);
		oddjob_free(task);
		snprintf(buf, sizeof(buf),
			 "Error at fork(): %s.\n", strerror(errno));
		if (globals.debug) {
			fprintf(stderr, "%s\n", buf);
		}
		oddjob_dbus_send_message_response_error(msg,
							ODDJOB_ERROR_INTERNAL,
							buf);
		return;
		break;
	case 0:
		if (globals.debug) {
			fprintf(stderr, "Child preparing to exec %s",
				method->argv[0]);
			for (i = 0; method->argv[i] != NULL; i++) {
				fprintf(stderr, "%s %s\"%s\"%s",
					(i > 0) ? "," : "",
					(i == 0) ? "(" : "",
					method->argv[i],
					(method->argv[i + 1] == NULL) ?
					")" : "");
			}
			fprintf(stderr, "\n");
		}
		/* We're the child -- close the read end of the error pipe, and
		 * mark its write end to be closed on successful exec(). */
		close(exec_status[0]);
		/* Set up stdio. */
		close(child_in[1]);
		close(child_out[0]);
		close(child_err[0]);
		dup2(child_in[0], 0);
		dup2(child_out[1], 1);
		dup2(child_err[1], 2);
		dup2(exec_status[1], 3);
		i = fcntl(3, F_GETFD);
		fcntl(3, F_SETFD, i | FD_CLOEXEC);
		/* Close any open descriptors which aren't the exec status pipe
		 * or stdio. */
		for (i = sysconf(_SC_OPEN_MAX) - 1; i > 3; i--) {
			close(i);
		}
		/* set up the environment */
		putenv(task->service);
		putenv(task->path);
		putenv(task->interface);
		putenv(task->method);
		putenv(task->calling_user);
#ifdef SELINUX_ACLS
		/* Set up the SELinux execution context. */
		if (globals.selinux_enabled) {
			const char *client_secontext;
			security_context_t helper_context, exec_context;

			client_secontext = oddjob_dbus_message_get_selinux_context(msg);
			if (client_secontext == NULL) {
				/* Wha....? */
				exec_errno = 0xff;
				write(3, &exec_errno, 1);
				_exit(-1);
			}
			if (getfilecon(method->argv[0], &helper_context) == -1) {
				switch (errno) {
				/* Not there? */
				case ENOENT:
					exec_errno = errno;
					break;
				default:
					/* No label? */
					exec_errno = 0xfd;
					break;
				}
				write(3, &exec_errno, 1);
				_exit(-1);
			}
			if (security_compute_create((char *) client_secontext,
						    helper_context,
						    SECCLASS_PROCESS,
						    &exec_context) != 0) {
				/* Failed to compute exec context? */
				exec_errno = 0xfe;
				write(3, &exec_errno, 1);
				_exit(-1);
			}
			if (setexeccon(exec_context) == -1) {
				/* Failed to set exec context? */
				exec_errno = 0xfc;
				write(3, &exec_errno, 1);
				_exit(-1);
			}
		}
#endif
		/* run the helper */
		execv(method->argv[0], task->argv);
		/* uh-oh. send errno to the caller and bail */
		exec_errno = errno;
		write(3, &exec_errno, 1);
		_exit(-1);
		break;
	default:
		break;
	}
	/* We're the parent -- no need for things which only the child, uh,
	 * needs. */
	oddjob_free(task->argv);
	task->argv = NULL;
	oddjob_free(task->service);
	task->service = NULL;
	oddjob_free(task->path);
	task->path = NULL;
	oddjob_free(task->interface);
	task->interface = NULL;
	oddjob_free(task->method);
	task->method = NULL;
	oddjob_free(task->calling_user);
	task->calling_user = NULL;
	/* Check the exec() status, hoping that the child actually gets to run
	 * within a reasonable time. */
	close(exec_status[1]);
	close(child_in[0]);
	close(child_out[1]);
	close(child_err[1]);
	while ((i = (read(exec_status[0], &exec_errno, 1))) == -1) {
		continue;
	}
	close(exec_status[0]);
	/* If we actually got a byte, then it's an exec() errno. */
	if (i == 1) {
		const char *message;
		close(task->stdin_fd);
		close(task->stdout_fd);
		close(task->stderr_fd);
		waitpid(task->pid, &status, 0);
		switch (exec_errno) {
		case 0xff:
			message = "error determining SELinux context of caller";
			break;
		case 0xfd:
			message = "error reading SELinux file context of "
				  "helper";
			break;
		case 0xfe:
			message = "error determining helper execution SELinux "
				  "context";
			break;
		case 0xfc:
			message = "error setting helper execution SELinux "
				  "context";
			break;
		default:
			message = strerror(exec_errno);
			break;
		}
		snprintf(buf, sizeof(buf),
			 "Child signalled exec() error: %s.", message);
		if (globals.debug) {
			fprintf(stderr, "%s\n", buf);
		}
		oddjob_dbus_send_message_response_error(msg,
							ODDJOB_ERROR_EXEC,
							buf);
		task->pid = getpid();
		oddjob_buffer_free(task->stdin_buffer);
		oddjob_buffer_free(task->stdout_buffer);
		oddjob_buffer_free(task->stderr_buffer);
		oddjob_dbus_message_free(task->msg);
		oddjob_free(task->service);
		oddjob_free(task->path);
		oddjob_free(task->interface);
		oddjob_free(task->method);
		oddjob_free(task->calling_user);
		oddjob_free(task->argv);
		oddjob_free(task);
		return;
	}
	/* Exec() succeeded -- hook up the buffers to the main loop and wait
	 * for something interesting to happen. */
	mainloop_oddjob_watch_add(task->stdin_fd,
				  DBUS_WATCH_WRITABLE | DBUS_WATCH_ERROR,
				  oddjob_watch_service, task);
	mainloop_oddjob_watch_add(task->stdout_fd,
				  DBUS_WATCH_READABLE | DBUS_WATCH_ERROR,
				  oddjob_watch_service, task);
	mainloop_oddjob_watch_add(task->stderr_fd,
				  DBUS_WATCH_READABLE | DBUS_WATCH_ERROR,
				  oddjob_watch_service, task);
}

/* Get a list of the available methods. */
static void
oddjobd_list_methods(struct oddjob_dbus_context *ctx,
		     struct oddjob_dbus_message *msg,
		     const char *service_name,
		     const char *object_path,
		     const char *interface_name,
		     const char *method_name,
		     const char *user,
		     unsigned long uid,
		     void *data,
		     dbus_bool_t list_all)
{
	int i, j, k, l;
	char *result, *t;
	char fmt[] = "(service=\"%s\",object=\"%s\","
		     "interface=\"%s\",method=\"%s\")";
	struct oddjob_config *config;
	struct service *service;
	struct object *object;
	struct interface *interface;
	struct method *method;
	const char *client_secontext;
	client_secontext = oddjob_dbus_message_get_selinux_context(msg);
	/* First check the list method. */
	method = data;
	if (globals.debug) {
		fprintf(stderr,
			"Received request for \"%s:%s:%s:%s\" from %s.\n",
			service_name, object_path, interface_name, method_name,
			user);
	}
	if (check_method_acl(method, user, uid, client_secontext) !=
	    oddjob_acl_allow) {
		if (globals.debug) {
			fprintf(stderr, "Request for \"%s\" denied.\n",
				method->name);
		}
		oddjob_dbus_send_message_response_error(msg,
							ODDJOB_ERROR_ACL,
							"ACL does not allow access");
		return;
	}
	result = NULL;
	config = method->interface->object->service->config;
	for (i = 0; i < config->n_services; i++) {
		service = &config->services[i];
		for (j = 0; j < service->n_objects; j++) {
			object = &service->objects[j];
			for (k = 0; k < object->n_interfaces; k++) {
				interface = &object->interfaces[k];
				for (l = 0; l < interface->n_methods; l++) {
					method = &interface->methods[l];
					if (list_all || (check_method_acl(method, user, uid, client_secontext) == oddjob_acl_allow)) {
						if (result == NULL) {
							t = oddjob_malloc0(strlen(fmt) + 2 +
									   strlen(service->name) + 1 +
									   strlen(object->name) + 1 +
									   strlen(interface->name) + 1 +
									   strlen(method->name) + 1);
							sprintf(t, fmt,
								service->name,
								object->name,
								interface->name,
								method->name);
							result = t;
						} else {
							t = oddjob_malloc0(strlen(result) + 1 +
									   strlen(fmt) + 2 +
									   strlen(service->name) + 1 +
									   strlen(object->name) + 1 +
									   strlen(interface->name) + 1 +
									   strlen(method->name) + 1);
							strcpy(t, result);
							strcat(t, ",");
							sprintf(t + strlen(t), fmt,
								service->name,
								object->name,
								interface->name,
								method->name);
							oddjob_free(result);
							result = t;
						}
					}
				}
			}
		}
	}
	oddjob_dbus_send_message_response_text(msg, 0, result, FALSE);
	oddjob_free(result);
}

/* Get a list of the methods available to the caller. */
static void
oddjobd_list_method(struct oddjob_dbus_context *ctx,
		    struct oddjob_dbus_message *msg,
		    const char *service_name,
		    const char *object_path,
		    const char *interface_name,
		    const char *method_name,
		    const char *user,
		    unsigned long uid,
		    void *data)
{
	oddjobd_list_methods(ctx, msg,
			     service_name, object_path,
			     interface_name, method_name,
			     user, uid, data,
			     FALSE);
}

/* Get a list of all configured methods. */
static void
oddjobd_list_all_method(struct oddjob_dbus_context *ctx,
			struct oddjob_dbus_message *msg,
			const char *service_name,
			const char *object_path,
			const char *interface_name,
			const char *method_name,
			const char *user,
			unsigned long uid,
			void *data)
{
	oddjobd_list_methods(ctx, msg,
			     service_name, object_path,
			     interface_name, method_name,
			     user, uid, data,
			     TRUE);
}

/* Return introspection data for this object. */
static void
oddjobd_introspect_method(struct oddjob_dbus_context *ctx,
			  struct oddjob_dbus_message *msg,
			  const char *service_name,
			  const char *object_path,
			  const char *interface_name,
			  const char *method_name,
			  const char *user,
			  unsigned long uid,
			  void *data)
{
	struct oddjob_config *config;
	struct service *service;
	struct object *object;
	struct interface *interface;
	struct method *method;
	const char *client_secontext;
	char *text, *t, *memberlist, *interfacelist, *nodelist;
	int i, j, k;

	client_secontext = oddjob_dbus_message_get_selinux_context(msg);
	method = data;
	if (globals.debug) {
		fprintf(stderr,
			"Received request for \"%s:%s:%s:%s\" from %s.\n",
			service_name, object_path, interface_name, method_name,
			user);
	}

	if (check_method_acl(method, user, uid,
			     oddjob_dbus_message_get_selinux_context(msg)) !=
	    oddjob_acl_allow) {
		if (globals.debug) {
			fprintf(stderr, "Request for \"%s\" denied to %s.\n",
				method->name, user);
		}
		oddjob_dbus_send_message_response_error(msg,
							ODDJOB_ERROR_ACL,
							"ACL does not allow access");
		return;
	}

	/* Search for the service. */
	config = method->interface->object->service->config;
	for (i = 0; i < config->n_services; i++) {
		service = &config->services[i];
		if (strcmp(service->name, service_name) == 0) {
			break;
		}
	}
	if (i >= config->n_services) {
		return;
	}

	/* Search for the object. */
	for (i = 0; i < service->n_objects; i++) {
		object = &service->objects[i];
		if (fnmatch(object->name, object_path,
			    ODDJOB_OBJECT_FNMATCH_FLAGS) == 0) {
			break;
		}
	}
	if (i >= service->n_objects) {
		return;
	}

	/* Build a set of immediate child nodes. */
	j = strlen(object->name);
	nodelist = NULL;
	for (i = 0; i < service->n_objects; i++) {
		k = strlen(service->objects[i].name);
		/* If the current object's an initial substring of the
 		 * candidate object, then we consider the candidate a child. */
		if ((j < k) &&
		    (strncmp(object->name, service->objects[i].name, j) == 0)) {
			char *p;
			p = service->objects[i].name + j;
			/* Let's just make sure there's something here. */
			if ((*p == '/') || (strcmp(object->name, "/") == 0)) {
				if (*p == '/') {
					p++;
				}
				if (strlen(p) == (strcspn(p, "/"))) {
					/* The child's name is t[0..(k-1)]. */
					if (nodelist == NULL) {
						t = oddjob_malloc0(strlen(ODDJOB_INTROSPECTION_NODE) + k + 1);
						sprintf(t, ODDJOB_INTROSPECTION_NODE, p);
						nodelist = t;
					} else {
						t = oddjob_malloc0(strlen(nodelist) +
								   strlen(ODDJOB_INTROSPECTION_NODE) + k + 1);
						strcpy(t, nodelist);
						sprintf(t + strlen(t), ODDJOB_INTROSPECTION_NODE, p);
						free(nodelist);
						nodelist = t;
					}
				}
			}
		}
	}

	/* Build the set of allowed interfaces and methods. */
	interfacelist = NULL;
	for (i = 0; i < object->n_interfaces; i++) {
		interface = &object->interfaces[i];
		memberlist = NULL;
		for (j = 0; j < interface->n_methods; j++) {
			method = &interface->methods[j];
			if (check_method_acl(method, user, uid, client_secontext) == oddjob_acl_allow) {
				if (memberlist == NULL) {
					/* New member list. */
					t = oddjob_malloc0(strlen(ODDJOB_INTROSPECTION_METHOD_START) +
							   strlen(method->name) +
							   strlen(ODDJOB_INTROSPECTION_METHOD_ARGUMENT) * method->n_arguments +
							   strlen(ODDJOB_INTROSPECTION_ODDJOB_METHOD_END) +
							   1);
					sprintf(t, ODDJOB_INTROSPECTION_METHOD_START, method->name);
					for (k = 0;
					     k < method->n_arguments;
					     k++) {
						strcat(t, ODDJOB_INTROSPECTION_METHOD_ARGUMENT);
					}
					if (method->handler == oddjobd_introspect_method) {
						strcat(t, ODDJOB_INTROSPECTION_DBUS_METHOD_END);
					} else {
						strcat(t, ODDJOB_INTROSPECTION_ODDJOB_METHOD_END);
					}
					memberlist = t;
				} else {
					/* New addition for member list. */
					t = oddjob_malloc0(strlen(memberlist) +
							   strlen(ODDJOB_INTROSPECTION_METHOD_START) +
							   strlen(method->name) +
							   strlen(ODDJOB_INTROSPECTION_METHOD_ARGUMENT) * method->n_arguments +
							   strlen(ODDJOB_INTROSPECTION_ODDJOB_METHOD_END) +
							   1);
					strcpy(t, memberlist);
					sprintf(t + strlen(t), ODDJOB_INTROSPECTION_METHOD_START, method->name);
					for (k = 0;
					     k < method->n_arguments;
					     k++) {
						strcat(t, ODDJOB_INTROSPECTION_METHOD_ARGUMENT);
					}
					if (method->handler == oddjobd_introspect_method) {
						strcat(t, ODDJOB_INTROSPECTION_DBUS_METHOD_END);
					} else {
						strcat(t, ODDJOB_INTROSPECTION_ODDJOB_METHOD_END);
					}
					oddjob_free(memberlist);
					memberlist = t;
				}
			}
		}
		if (memberlist != NULL) {
			if (interfacelist == NULL) {
				/* New interface list. */
				t = oddjob_malloc0(strlen(ODDJOB_INTROSPECTION_INTERFACE_START) +
						   strlen(interface->name) +
						   strlen(memberlist) +
						   strlen(ODDJOB_INTROSPECTION_INTERFACE_END) +
						   1);
				sprintf(t, ODDJOB_INTROSPECTION_INTERFACE_START, interface->name);
				strcat(t, memberlist);
				strcat(t, ODDJOB_INTROSPECTION_INTERFACE_END);
				interfacelist = t;
			} else {
				/* New addition for interface list. */
				t = oddjob_malloc0(strlen(interfacelist) +
						   strlen(ODDJOB_INTROSPECTION_INTERFACE_START) +
						   strlen(interface->name) +
						   strlen(memberlist) +
						   strlen(ODDJOB_INTROSPECTION_INTERFACE_END) +
						   1);
				strcpy(t, interfacelist);
				sprintf(t + strlen(t), ODDJOB_INTROSPECTION_INTERFACE_START, interface->name);
				strcat(t, memberlist);
				strcat(t, ODDJOB_INTROSPECTION_INTERFACE_END);
				oddjob_free(interfacelist);
				interfacelist = t;
			}
			oddjob_free(memberlist);
		}
	}

	/* Always return introspection data. */
	if (interfacelist == NULL) {
		oddjob_dbus_send_message_response_error(msg,
							ODDJOB_ERROR_NO_OBJECT,
							object_path ?
							object_path : "");
		if (nodelist != NULL) {
			oddjob_free(nodelist);
		}
	} else {
		text = oddjob_malloc0(strlen(ODDJOB_INTROSPECTION_HEADER) +
				      (nodelist ? strlen(nodelist) : 0) +
				      strlen(interfacelist) +
				      strlen(ODDJOB_INTROSPECTION_FOOTER) +
				      1);
		strcpy(text, ODDJOB_INTROSPECTION_HEADER);
		if (nodelist != NULL) {
			strcat(text, nodelist);
			oddjob_free(nodelist);
		}
		strcat(text, interfacelist);
		oddjob_free(interfacelist);
		strcat(text, ODDJOB_INTROSPECTION_FOOTER);
		/* Send the data. */
		oddjob_dbus_send_introspection_text(msg, text);
		oddjob_free(text);
	}
}

/* Cause the server to shut down. */
static void
oddjobd_quit_method(struct oddjob_dbus_context *ctx,
		    struct oddjob_dbus_message *msg,
		    const char *service_name,
		    const char *object_path,
		    const char *interface_name,
		    const char *method_name,
		    const char *user,
		    unsigned long uid,
		    void *data)
{
	struct method *method;
	const char *client_secontext;

	client_secontext = oddjob_dbus_message_get_selinux_context(msg);
	method = data;
	if (globals.debug) {
		fprintf(stderr,
			"Received request for \"%s:%s:%s:%s\" from %s.\n",
			service_name, object_path, interface_name, method_name,
			user);
	}
	if (check_method_acl(method, user, uid, client_secontext) !=
	    oddjob_acl_allow) {
		if (globals.debug) {
			fprintf(stderr, "Request for \"%s\" denied to %s.\n",
				method->name, user);
		}
		oddjob_dbus_send_message_response_error(msg,
							ODDJOB_ERROR_ACL,
							"ACL does not allow access");
		return;
	}
	if (globals.debug) {
		fprintf(stderr, "Shutting down.\n");
	}
	oddjob_dbus_send_message_response_text(msg, 0, "", FALSE);
	globals.quit++;
}

static void
method_add_internal(struct oddjob_config *config,
		    const char *service_name, const char *object_name,
		    const char *interface_name, const char *method_name,
		    oddjob_dbus_handler handler)
{
	int i;
	struct service *service;
	struct object *object;
	struct interface *interface;
	struct method *method;
	for (i = 0; i < config->n_services; i++) {
		service = &config->services[i];
		if (strcmp(service->name, service_name) == 0) {
			break;
		}
	}
	if (i >= config->n_services) {
		service = service_add(config, service_name);
	}
	for (i = 0; i < service->n_objects; i++) {
		object = &service->objects[i];
		if (strcmp(object->name, object_name) == 0) {
			break;
		}
	}
	if (i >= service->n_objects) {
		object = object_add(service, object_name);
	}
	for (i = 0; i < object->n_interfaces; i++) {
		interface = &object->interfaces[i];
		if (strcmp(interface->name, interface_name) == 0) {
			break;
		}
	}
	if (i >= object->n_interfaces) {
		interface = interface_add(object, interface_name);
	}
	for (i = 0; i < interface->n_methods; i++) {
		method = &interface->methods[i];
		if (strcmp(method->name, method_name) == 0) {
			break;
		}
	}
	if (i >= interface->n_methods) {
		method = method_add(interface, method_name);
	}
	if (method->type != method_invalid) {
		abort();
	}
	method->type = method_internal;
	method->n_arguments = 0;
	method->handler = handler;
	method->argv = NULL;
	method->prepend_user = FALSE;
	method->argument_passing_method = oddjob_argument_passing_invalid;
}

static void 
config_add_internal_methods(struct oddjob_config *config)
{
	method_add_internal(config, ODDJOB_SERVICE_NAME, ODDJOB_OBJECT_PATH,
			    ODDJOB_INTERFACE_NAME, "quit",
			    oddjobd_quit_method);
	method_add_internal(config, ODDJOB_SERVICE_NAME, ODDJOB_OBJECT_PATH,
			    ODDJOB_INTERFACE_NAME, "reload",
			    oddjobd_reload_method);
	method_add_internal(config, ODDJOB_SERVICE_NAME, ODDJOB_OBJECT_PATH,
			    ODDJOB_INTERFACE_NAME, ODDJOB_LIST_REQUESTS_METHOD,
			    oddjobd_list_method);
	method_add_internal(config, ODDJOB_SERVICE_NAME, ODDJOB_OBJECT_PATH,
			    ODDJOB_INTERFACE_NAME,
			    ODDJOB_LIST_ALL_REQUESTS_METHOD,
			    oddjobd_list_all_method);
}

static dbus_bool_t
object_has_method(struct object *obj, const char *interface, const char *method)
{
	int i, j;
	for (i = 0; i < obj->n_interfaces; i++) {
		if (strcmp(obj->interfaces[i].name, interface) != 0) {
			continue;
		}
		for (j = 0; j < obj->interfaces[i].n_methods; j++) {
			if ((strcmp(obj->interfaces[i].methods[j].name,
				    method) == 0) &&
			    (obj->interfaces[i].methods[j].handler != NULL)) {
				return TRUE;
			}
		}
	}
	return FALSE;
}

static void
config_add_introspection_methods(struct oddjob_config *config)
{
	int i, j, k;
	struct service *service;
	struct object *object, *object2;
	char *p, *q;
	/* Now add our handlers to the list which our D-Bus layer knows. */
	for (i = 0; i < config->n_services; i++) {
		service = &config->services[i];
		/* Set up the service's explicitly-defined objects. */
		for (j = 0; j < service->n_objects; j++) {
			object = &service->objects[j];
			/* Now that we've registered the object, register its
			 * introspection interface. */
			if (object_has_method(object,
					      ODDJOB_INTROSPECTION_INTERFACE,
					      ODDJOB_INTROSPECTION_METHOD)) {
				continue;
			}
			method_add_internal(config,
					    service->name,
					    object->name,
					    ODDJOB_INTROSPECTION_INTERFACE,
					    ODDJOB_INTROSPECTION_METHOD,
					    oddjobd_introspect_method);
			/* Now supply any missing parents. */
			p = oddjob_malloc0(strlen(object->name) + 1);
			strcpy(p, object->name);
			for (q = p + strlen(p); q >= p; q--) {
				if (*q == '/') {
					if (p == q) {
						q[1] = '\0';
					} else {
						q[0] = '\0';
					}
					for (k = 0;
					     k < service->n_objects;
					     k++) {
						object2 = &service->objects[k];
						if (strcmp(object2->name,
							   p) == 0) {
							break;
						}
					}
					if (k >= service->n_objects) {
						method_add_internal(config,
								    service->name,
								    p,
								    ODDJOB_INTROSPECTION_INTERFACE,
								    ODDJOB_INTROSPECTION_METHOD,
								    oddjobd_introspect_method);
					}
				}
			}
			free(p);
		}
	}
}

static struct method *
config_method(struct oddjob_config *config,
	      const char *service_name,
	      const char *object_name,
	      const char *interface_name,
	      const char *method_name)
{
	int i;
	struct service *service;
	struct object *object;
	struct interface *interface;
	struct method *method;
	/* Find the matching service. */
	for (i = 0; i < config->n_services; i++) {
		service = &config->services[i];
		if (strcmp(service->name, service_name) == 0) {
			break;
		}
	}
	if (i >= config->n_services) {
		return NULL;
	}
	/* Find the matching object. */
	for (i = 0; i < service->n_objects; i++) {
		object = &service->objects[i];
		if (strcmp(object->name, object_name) == 0) {
			break;
		}
	}
	if (i >= service->n_objects) {
		return NULL;
	}
	/* Find the matching interface. */
	for (i = 0; i < object->n_interfaces; i++) {
		interface = &object->interfaces[i];
		if (strcmp(interface->name, interface_name) == 0) {
			break;
		}
	}
	if (i >= object->n_interfaces) {
		return NULL;
	}
	/* Search for the matching method. */
	for (i = 0; i < interface->n_methods; i++) {
		method = &interface->methods[i];
		if (strcmp(method->name, method_name) == 0) {
			return method;
		}
	}
	return NULL;
}

static dbus_bool_t
config_contains(struct oddjob_config *config,
	        const char *service_name,
	        const char *object_name,
	        const char *interface_name,
	        const char *method_name)
{
	return (config_method(config,
			      service_name,
			      object_name,
			      interface_name,
			      method_name) != NULL);
}

static int
config_register(struct oddjob_dbus_context *ctx, struct oddjob_config *config,
		struct oddjob_config *old_config)
{
	int i, j, k, l;
	dbus_bool_t reg;
	struct service *service;
	struct object *object;
	struct interface *interface;
	struct method *method;
	/* Now add our handlers to the list which our D-Bus layer knows. */
	for (i = 0; i < config->n_services; i++) {
		service = &config->services[i];
		/* Set up the service's explicitly-defined objects. */
		for (j = 0; j < service->n_objects; j++) {
			object = &service->objects[j];
			object->service = service;
			/* Set up the object's explicitly-defined interfaces. */
			for (k = 0; k < object->n_interfaces; k++) {
				interface = &object->interfaces[k];
				interface->object = object;
				for (l = 0; l < interface->n_methods; l++) {
					method = &interface->methods[l];
					method->interface = interface;
					if (globals.debug) {
						if ((old_config == NULL) ||
						    !config_contains(old_config,
								     service->name,
								     object->name,
								     interface->name,
								     method->name)) {
							fprintf(stderr, "Adding new handler for (\"%s\",\"%s\",\"%s\",\"%s\").\n",
								service->name,
								object->name,
								interface->name,
								method->name);
						}
					}
					/* If the handler used NULL, give it
					 * the method structure address, which
					 * wasn't fixed until now. */
					reg = oddjob_dbus_listener_add_method(ctx,
									      service->name,
									      object->name,
									      interface->name,
									      method->name,
									      method->n_arguments,
									      method->handler,
									      method);
					if (!reg) {
						fprintf(stderr, "Error initializing service \"%s\"!\n",
							service->name);
						return 1;
					}
				}
			}
		}
	}
	return 0;
}

static void
config_unregister_removed(struct oddjob_dbus_context *ctx,
			  struct oddjob_config *old_config,
			  struct oddjob_config *new_config)
{
	int i, j, k, l;
	struct service *service;
	struct object *object;
	struct interface *interface;
	struct method *method;
	/* Iterate over all services. */
	for (i = 0; i < old_config->n_services; i++) {
		service = &old_config->services[i];
		/* Iterate over all objects. */
		for (j = 0; j < service->n_objects; j++) {
			object = &service->objects[j];
			/* Iterate over all interafaces. */
			for (k = 0; k < object->n_interfaces; k++) {
				interface = &object->interfaces[k];
				/* Iterate over all methods. */
				for (l = 0; l < interface->n_methods; l++) {
					method = &interface->methods[l];
					/* If the method isn't in the new
					 * configuration, remove it from the
					 * D-Bus listener's registry. */
					if (!config_contains(new_config,
							     service->name,
							     object->name,
							     interface->name,
							     method->name)) {
						if (globals.debug) {
							fprintf(stderr,
								"Unregistering (\"%s\",\"%s\",\"%s\",\"%s\").\n",
								service->name,
								object->name,
								interface->name,
								method->name);
						}
						oddjob_dbus_listener_remove_method(ctx,
										   service->name,
										   object->name,
										   interface->name,
										   method->name);
					}
				}
			}
		}
	}
}

static dbus_bool_t
oddjobd_reload_configuration(struct oddjob_dbus_context *ctx,
			     const char **error_reason)
{
	struct oddjob_config *new_config, *old_config;

	/* Allocate a new configuration structure. */
	new_config = oddjob_malloc0(sizeof(struct oddjob_config));

	/* Add our built-in handlers to the list of methods which we need to
	 * register. */
	config_add_internal_methods(new_config);

	/* Read in ACLs and definitions for external handlers. */
	if (!load_config(new_config, globals.configfile, FALSE)) {
		unload_config(new_config);
		if (error_reason) {
			*error_reason = "Error reading new configuration.";
		}
		return FALSE;
	}

	/* Add introspection methods to every object. */
	config_add_introspection_methods(new_config);

	/* Remove methods which we will no longer be providing. */
	config_unregister_removed(ctx, globals.config, new_config);

	/* Switch to the new configuration. */
	old_config = globals.config;
	globals.config = new_config;

	/* Register all of our methods with the D-Bus layer. */
	if (config_register(ctx, new_config, old_config) != 0) {
		unload_config(old_config);
		if (error_reason) {
			*error_reason = "Error registering with D-Bus layer.";
		}
		return FALSE;
	} else {
		unload_config(old_config);
		return TRUE;
	}
}

static void
oddjobd_reload_method(struct oddjob_dbus_context *ctx,
		      struct oddjob_dbus_message *msg,
		      const char *service_name,
		      const char *object_path,
		      const char *interface_name,
		      const char *method_name,
		      const char *user,
		      unsigned long uid,
		      void *data)
{
	struct method *method;
	const char *reason;

	method = data;

	if (globals.debug) {
		fprintf(stderr,
			"Received request for \"%s:%s:%s:%s\" from %s.\n",
			service_name, object_path, interface_name, method_name,
			user);
	}
	if (check_method_acl(method, user, uid,
			     oddjob_dbus_message_get_selinux_context(msg)) !=
	    oddjob_acl_allow) {
		if (globals.debug) {
			fprintf(stderr, "Request for \"%s\" denied to %s.\n",
				method->name, user);
		}
		oddjob_dbus_send_message_response_error(msg,
							ODDJOB_ERROR_ACL,
							"ACL does not allow access");
		return;
	}

	reason = NULL;
	if (oddjobd_reload_configuration(ctx, &reason)) {
		oddjob_dbus_send_message_response_text(msg,
						       0,
						       "Reload succeeded.",
						       FALSE);
	} else {
		oddjob_dbus_send_message_response_error(msg,
							ODDJOB_ERROR_INTERNAL,
							reason);
	}
}

static void
signal_handler(int signum)
{
	if (signum == SIGHUP) {
		globals.reload++;
	}
}

int
main(int argc, char **argv)
{
	struct oddjob_dbus_context *ctx;
	FILE *pidfile;
	gid_t gid;
	int c, pidfd;
	const char *basename, *usage;
	char *p;
	struct {
		dbus_bool_t nofork;
		const char *pidfile;
		int reconnect_timeout;
		DBusBusType bus;
	} options = {
		.nofork = FALSE,
		.pidfile = NULL,
		.reconnect_timeout = DEFAULT_RECONNECT_TIMEOUT,
		.bus = DBUS_BUS_SYSTEM,
	};
	struct oddjob_config *config;
	struct sigaction action;

	/* If we need to provide a usage message, then we need the basename of
	 * the binary. */
	basename = argv[0];
	if (strchr(basename, '/')) {
		basename = strrchr(basename, '/') + 1;
	}

	/* Process command-line options. */
	usage = "Usage: %s [-d] [-n] [-p pidfile] [-c configfile] [-S] "
		"[-t timeout]\n";
	while ((c = getopt(argc, argv, "dnp:c:St:")) != -1) {
		switch (c) {
		case 'd':
			globals.debug++;
			/* fall through */
		case 'n':
			options.nofork = TRUE;
			break;
		case 'p':
			options.pidfile = optarg;
			break;
		case 'c':
			globals.configfile = optarg;
			break;
		case 'S':
			options.bus = DBUS_BUS_SESSION;
			break;
		case 't':
			options.reconnect_timeout = strtol(optarg, &p, 0);
			if ((p == NULL) || (p == optarg) || (*p != '\0')) {
				printf(usage, basename);
				return 1;
			}
			break;
		default:
			printf(usage, basename);
			return 1;
			break;
		}
	}
	if ((argc - optind) > 0) {
		printf(usage, basename);
		return 1;
	}

	/* We need a global configuration. */
	config = oddjob_malloc0(sizeof(struct oddjob_config));

	/* Add our built-in handlers to the list of methods which we need to
	 * register. */
	config_add_internal_methods(config);

	/* Read in ACLs and definitions for external handlers. */
	if (!load_config(config, globals.configfile, FALSE)) {
		fprintf(stderr, "Error loading configuration!\n");
		return 1;
	}
	globals.config = config;

	/* Open a connection to the message bus. */
	ctx = oddjob_dbus_listener_new(options.bus);
	if (ctx == NULL) {
		fprintf(stderr, "Error connecting to D-Bus!\n");
		return 2;
	}
	oddjob_dbus_listener_set_reconnect_timeout(ctx,
						   options.reconnect_timeout);

	/* Add introspection methods to every object. */
	config_add_introspection_methods(config);

	/* Register all of our methods with the D-Bus layer. */
	if (config_register(ctx, config, NULL) != 0) {
		fprintf(stderr, "Error registering with D-Bus layer!\n");
		return 1;
	}

	/* Clear the supplemental group list.  We assume that we were started
	 * with the right UID/GID values, but there should be no need to keep
	 * the rest of the group memberships if we're a system-wide service. */
	if (options.bus == DBUS_BUS_SYSTEM) {
		gid = getgid();
		if (setgroups(1, &gid) == -1) {
			fprintf(stderr, "Error clearing supplemental group "
				"list!\n");
			return 1;
		}
	}

	/* Create a pidfile. */
	pidfd = -1;
	if (options.pidfile != NULL) {
		pidfd = open(options.pidfile, O_CREAT | O_WRONLY | O_TRUNC,
			     S_IRUSR | S_IWUSR);
		if (pidfd == -1) {
			fprintf(stderr, "Error creating pidfile!\n");
			return 1;
		}
	}

	/* Change the working directory to the root directory. */
	if (chdir("/") == -1) {
		fprintf(stderr, "Error changing working directory to \"/\"!\n");
		return 1;
	}

	/* Prepare for reload signals. */
	memset(&action, 0, sizeof(action));
	sigemptyset(&action.sa_mask);
	action.sa_handler = signal_handler;
	if (sigaction(SIGHUP, &action, NULL) != 0) {
		fprintf(stderr, "Error setting SIGHUP handler (%s)\n",
			strerror(errno));
		return 1;
	}
	if (sigaction(SIGPIPE, &action, NULL) != 0) {
		fprintf(stderr, "Error setting SIGPIPE handler (%s)\n",
			strerror(errno));
		return 1;
	}

	/* Become a daemon, changing the working directory to the root,
	 * dissociating from the controlling terminal (if there is one),
	 * calling fork(), and letting the parent exit. */
	if (!options.nofork) {
		if (daemon(0, 0) != 0) {
			fprintf(stderr, "Error becoming a daemon!\n");
			if (options.pidfile != NULL) {
				unlink(options.pidfile);
			}
			return 1;
		}
	}

	/* Store our PID in the pidfile. */
	pidfile = fdopen(pidfd, "w");
	if (pidfile != NULL) {
		fprintf(pidfile, "%lu", (long) getpid());
		fclose(pidfile);
	}

	/* Now sit! */
	oddjob_dbus_main_init(ctx);
	globals.quit = 0;
	while (globals.quit == 0) {
		if (globals.reload) {
			oddjobd_reload_configuration(ctx, NULL);
			globals.reload = 0;
		}
		oddjob_dbus_listener_reconnect_if_needed(ctx);
		oddjob_dbus_main_iterate(ctx);
	}
	oddjob_dbus_main_done(ctx);

	/* Clean up and exit. */
	unload_config(globals.config);
	oddjob_dbus_listener_free(ctx);
	if (options.pidfile != NULL) {
		unlink(options.pidfile);
	}

	return 0;
}
