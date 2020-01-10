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
#include <assert.h>
#include <fnmatch.h>
#include <limits.h>
#include <pwd.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dbus/dbus.h>
#include "buffer.h"
#include "common.h"
#include "mainloop.h"
#include "oddjob_dbus.h"
#include "util.h"

struct oddjob_dbus_context {
	DBusConnection *conn;
	DBusBusType bustype;
	dbus_bool_t registered;
	struct oddjob_dbus_service {
		char *name;
		struct oddjob_dbus_object {
			char *path;
			struct oddjob_dbus_interface {
				char *interface;
				struct oddjob_dbus_method {
					char *method;
					int n_arguments;
					oddjob_dbus_handler *handler;
					void *data;
				} *methods;
				int n_methods;
			} *interfaces;
			int n_interfaces;
		} *objects;
		int n_objects;
	} *services;
	int n_services;
	int reconnect_timeout;
};

struct oddjob_dbus_message {
	DBusConnection *conn;
	DBusMessage *msg;
	int32_t result;
	int n_args;
	char **args;
	char *selinux_context;
};

static dbus_bool_t
message_has_path(DBusMessage *message, const char *path)
{
#if DBUS_CHECK_VERSION(0,34,0)
	return dbus_message_has_path(message, path);
#elif DBUS_CHECK_VERSION(0,20,0)
	const char *msgpath;
	msgpath = dbus_message_get_path(message);
	if ((msgpath == NULL) && (path == NULL)) {
		return TRUE;
	}
	if ((msgpath != NULL) && (path != NULL) &&
	    (strcmp(msgpath, path) == 0)) {
		return TRUE;
	}
	return FALSE;
#else
#error "Don't know how to check message information in your version of D-Bus!"
#endif
}

static DBusHandlerResult
oddjob_dbus_filter(DBusConnection *conn, DBusMessage *message, void *user_data);

static int
oddjob_dbus_bind(DBusConnection *conn, const char *service_name)
{
#if DBUS_CHECK_VERSION(0,60,0)
        return dbus_bus_request_name(conn, service_name, 0, NULL);
#elif DBUS_CHECK_VERSION(0,30,0)
        return dbus_bus_request_name(conn, service_name,
				     DBUS_NAME_FLAG_PROHIBIT_REPLACEMENT, NULL);
#elif DBUS_CHECK_VERSION(0,20,0)
	return dbus_bus_acquire_service(conn, service_name,
					DBUS_SERVICE_FLAG_PROHIBIT_REPLACEMENT,
					NULL);
#else
#error "Don't know how to set service names for your version of D-Bus!"
	return FALSE;
#endif
}

static int
oddjob_dbus_unbind(DBusConnection *conn, const char *service_name)
{
#if DBUS_CHECK_VERSION(0,60,0)
        return dbus_bus_release_name(conn, service_name, NULL);
#else
#warning "Can't unregister services with this version of D-Bus."
	return FALSE;
#endif
}

void
oddjob_dbus_connection_close(DBusConnection *conn)
{
#if DBUS_CHECK_VERSION(0,34,0)
        dbus_connection_close(conn);
#elif DBUS_CHECK_VERSION(0,20,0)
	dbus_connection_disconnect(conn);
#else
#error "Don't know how to disconnect from your version of D-Bus!"
#endif
}

void
oddjob_dbus_listener_set_reconnect_timeout(struct oddjob_dbus_context *ctx,
					   int timeout)
{
	dbus_connection_set_exit_on_disconnect(ctx->conn, timeout <= 0);
	ctx->reconnect_timeout = timeout;
}

struct oddjob_dbus_context *
oddjob_dbus_listener_new(DBusBusType bustype)
{
	DBusError err;
	DBusConnection *conn;
	struct oddjob_dbus_context *ctx;

	memset(&err, 0, sizeof(err));
	conn = dbus_bus_get(bustype, &err);
	if (conn == NULL) {
		return NULL;
	}

	ctx = oddjob_malloc0(sizeof(struct oddjob_dbus_context));
	if (ctx == NULL) {
		return NULL;
	}

	ctx->bustype = bustype;
	ctx->conn = conn;

#if ! DBUS_CHECK_VERSION(0,22,0)
	/* According to johnp, we don't need to bother with any of this, but
	 * I've only verified it back as far as 0.22. */
	/* Request all messages which we're allowed to see. */
	dbus_bus_add_match(ctx->conn, "", &err);
#endif

	ctx->n_services = 0;
	ctx->reconnect_timeout = 0;
	ctx->services = NULL;

	return ctx;
}

void
oddjob_dbus_listener_free(struct oddjob_dbus_context *ctx)
{
	int i, j, k, l;
	if (ctx == NULL) {
		return;
	}
	for (i = 0; i < ctx->n_services; i++) {
		/* Clean up this service. */
		for (j = 0; j < ctx->services[i].n_objects; j++) {
			/* Clean up this object. */
			for (k = 0; k < ctx->services[i].objects[j].n_interfaces; k++) {
				/* Clean up this interface. */
				for (l = 0;
				     l < ctx->services[i].objects[j].interfaces[k].n_methods;
				     l++) {
					/* Clean up this method. */
					oddjob_free(ctx->services[i].objects[j].interfaces[k].methods[l].method);
					ctx->services[i].objects[j].interfaces[k].methods[l].method = NULL;
					ctx->services[i].objects[j].interfaces[k].methods[l].n_arguments = 0;
					ctx->services[i].objects[j].interfaces[k].methods[l].handler = NULL;
					ctx->services[i].objects[j].interfaces[k].methods[l].data = NULL;
				}
				oddjob_free(ctx->services[i].objects[j].interfaces[k].methods);
				ctx->services[i].objects[j].interfaces[k].methods = NULL;
				oddjob_free(ctx->services[i].objects[j].interfaces[k].interface);
				ctx->services[i].objects[j].interfaces[k].interface = NULL;
			}
			oddjob_free(ctx->services[i].objects[j].interfaces);
			ctx->services[i].objects[j].interfaces = NULL;
			oddjob_free(ctx->services[i].objects[j].path);
			ctx->services[i].objects[j].path = NULL;
		}
		oddjob_free(ctx->services[i].name);
		ctx->services[i].name = NULL;
		oddjob_free(ctx->services[i].objects);
		ctx->services[i].objects = NULL;
	}
	/* Clean up this service. */
	oddjob_free(ctx->services);
	ctx->services = NULL;
	ctx->n_services = 0;
	if (ctx->registered) {
		dbus_connection_remove_filter(ctx->conn,
					      oddjob_dbus_filter,
					      ctx);
		ctx->registered = FALSE;
	}
	/* Apparently we abort now when we try this. */
	/* oddjob_dbus_connection_close(ctx->conn); */
	ctx->conn = NULL;
	oddjob_free(ctx);
}

const char *
oddjob_dbus_message_get_selinux_context(struct oddjob_dbus_message *msg)
{
	return msg->selinux_context;
}

#ifdef SELINUX_ACLS
static char *
oddjob_dbus_get_selinux_context(DBusConnection *conn,
				const char *sender_bus_name)
{
	DBusMessage *query, *reply;
	char *ret;
	int length;
	DBusMessageIter iter, array;
	DBusError err;

	query = dbus_message_new_method_call(DBUS_SERVICE_DBUS,
					     DBUS_PATH_DBUS,
					     DBUS_INTERFACE_DBUS,
					     "GetConnectionSELinuxSecurityContext");
#if DBUS_CHECK_VERSION(0,30,0)
	dbus_message_append_args(query,
				 DBUS_TYPE_STRING, &sender_bus_name,
				 DBUS_TYPE_INVALID);
#elif DBUS_CHECK_VERSION(0,20,0)
	dbus_message_append_args(query,
				 DBUS_TYPE_STRING, sender_bus_name,
				 DBUS_TYPE_INVALID);
#else
#error	"Don't know how to set message arguments with your version of D-Bus!"
#endif

	memset(&err, 0, sizeof(err));
	reply = dbus_connection_send_with_reply_and_block(conn, query,
							  -1, &err);
	ret = NULL;
	if (dbus_error_is_set(&err)) {
#if DBUS_CHECK_VERSION(0,30,0)
		if ((strcmp(err.name, DBUS_ERROR_NAME_HAS_NO_OWNER) != 0) &&
		    (strcmp(err.name, DBUS_ERROR_NO_REPLY) != 0)) {
			fprintf(stderr, "Error %s: %s.\n",
				err.name, err.message);
		}
#elif DBUS_CHECK_VERSION(0,20,0)
		if ((strcmp(err.name, DBUS_ERROR_SERVICE_HAS_NO_OWNER) != 0) &&
		    (strcmp(err.name, DBUS_ERROR_NO_REPLY) != 0)) {
			fprintf(stderr, "Error %s: %s.\n",
				err.name, err.message);
		}
#else
#error	"Don't know what unknown-service/name errors look like with your version of D-Bus!"
#endif
	}
	if (reply != NULL) {
		if (dbus_message_iter_init(reply, &iter)) {
			switch (dbus_message_iter_get_arg_type(&iter)) {
			case DBUS_TYPE_ARRAY:
#if DBUS_CHECK_VERSION(0,33,0)
				/* We can't sanity check the length. */
				dbus_message_iter_recurse(&iter, &array);
				dbus_message_iter_get_fixed_array(&array, &ret,
								  &length);
				if (ret != NULL) {
					ret = oddjob_strndup(ret, length);
				}
#elif DBUS_CHECK_VERSION(0,20,0)
				/* We can't sanity check the length. */
				dbus_message_iter_get_byte_array(&iter,
								 (unsigned char **) &ret,
								 &length);
				if (ret != NULL) {
					ret = oddjob_strndup(ret, length);
				}
#else
#error "Don't know how to retrieve message arguments with your version of D-Bus!"
#endif
				break;
			case DBUS_TYPE_INVALID:
				break;
			default:
				break;
			}
		}
	}
	dbus_message_unref(query);
	if (reply != NULL) {
		dbus_message_unref(reply);
	}
	return ret;
}
#else
static char *
oddjob_dbus_get_selinux_context(DBusConnection *conn, const char *sender_bus_name)
{
	return NULL;
}
#endif

static void
oddjob_dbus_message_set_selinux_context(struct oddjob_dbus_message *msg,
					char *context_str)
{
	if (msg->selinux_context != NULL) {
		oddjob_free(msg->selinux_context);
		msg->selinux_context = NULL;
	}
	if (context_str != NULL) {
		msg->selinux_context = oddjob_strdup(context_str);
	}
}

static struct oddjob_dbus_message *
oddjob_dbus_message_from_message(DBusConnection *conn,
				 DBusMessage *message,
				 dbus_bool_t expect_an_int,
				 dbus_bool_t get_selinux_context)
{
	struct oddjob_dbus_message *msg;
	char *p, *context_str;
	const char *sender_bus_name;
	dbus_bool_t more;
	DBusMessageIter iter;
	int32_t i;

	msg = oddjob_malloc0(sizeof(struct oddjob_dbus_message));
	msg->conn = conn;
	dbus_connection_ref(msg->conn);
	msg->msg = message;
	if (msg->msg != NULL) {
		dbus_message_ref(msg->msg);
		if (dbus_message_iter_init(message, &iter)) {
			if (expect_an_int) {
				if (dbus_message_iter_get_arg_type(&iter) ==
				    DBUS_TYPE_INT32) {
#if DBUS_CHECK_VERSION(0,30,0)
					dbus_message_iter_get_basic(&iter, &i);
					msg->result = i;
#elif DBUS_CHECK_VERSION(0,20,0)
					i = dbus_message_iter_get_int32(&iter);
					msg->result = i;
#else
#error "Don't know how to retrieve message arguments with your version of D-Bus!"
#endif
				} else {
					msg->result = -1;
				}
			}
			more = TRUE;
			while (more) {
				switch (dbus_message_iter_get_arg_type(&iter)) {
				case DBUS_TYPE_STRING:
					oddjob_resize_array((void**) &msg->args,
							    sizeof(char*),
							    msg->n_args,
							    msg->n_args + 1);
#if DBUS_CHECK_VERSION(0,30,0)
					dbus_message_iter_get_basic(&iter, &p);
					msg->args[msg->n_args] = oddjob_strdup(p);
#elif DBUS_CHECK_VERSION(0,20,0)
					p = dbus_message_iter_get_string(&iter);
					msg->args[msg->n_args] = oddjob_strdup(p);
					dbus_free(p);
#else
#error "Don't know how to retrieve message arguments with your version of D-Bus!"
#endif
					msg->n_args++;
					break;
				case DBUS_TYPE_INVALID:
					more = FALSE;
					break;
				default:
					break;
				}
				if (!dbus_message_iter_has_next(&iter) ||
				    !dbus_message_iter_next(&iter)) {
					more = FALSE;
				}
			}
		}
		sender_bus_name = dbus_message_get_sender(msg->msg);
		if (sender_bus_name != NULL) {
			if (get_selinux_context) {
				context_str = oddjob_dbus_get_selinux_context(msg->conn, 
									      sender_bus_name);
			} else {
				context_str = NULL;
			}
			oddjob_dbus_message_set_selinux_context(msg, context_str);
			if (context_str != NULL) {
				oddjob_free(context_str);
			}
		}
	}

	return msg;
}

struct oddjob_dbus_message *
oddjob_dbus_message_dup(struct oddjob_dbus_message *input)
{
	struct oddjob_dbus_message *msg;
	int i;

	msg = oddjob_malloc0(sizeof(struct oddjob_dbus_message));
	msg->conn = input->conn;
	dbus_connection_ref(msg->conn);
	msg->msg = input->msg;
	if (msg->msg != NULL) {
		dbus_message_ref(msg->msg);
	}
	msg->result = input->result;
	msg->n_args = input->n_args;
	msg->args = NULL;
	oddjob_resize_array((void **) &msg->args, sizeof(char *),
			    0, msg->n_args);
	for (i = 0; i < msg->n_args; i++) {
		msg->args[i] = oddjob_strdup(input->args[i]);
	}
	if (input->selinux_context != NULL) {
		oddjob_dbus_message_set_selinux_context(msg,
							input->selinux_context);
	}
	return msg;
}

void
oddjob_dbus_message_free(struct oddjob_dbus_message *msg)
{
	int i;
	if (msg != NULL) {
		oddjob_dbus_message_set_selinux_context(msg, NULL);
		if (msg->args != NULL) {
			for (i = 0; i < msg->n_args; i++) {
				oddjob_free(msg->args[i]);
			}
			oddjob_free(msg->args);
		}
		msg->args = NULL;
		msg->n_args = 0;
		msg->result = -1;
		if (msg->msg != NULL) {
			dbus_message_unref(msg->msg);
			msg->msg = NULL;
		}
		if (msg->conn != NULL) {
			dbus_connection_unref(msg->conn);
			msg->conn = NULL;
		}
		oddjob_free(msg);
	}
}

void
oddjob_dbus_listener_reconnect_if_needed(struct oddjob_dbus_context *ctx)
{
	DBusConnection *newconn;
	DBusError err;
	int i, attempt;

	/* If we're still connected, we don't need to do anything. */
	if (dbus_connection_get_is_connected(ctx->conn)) {
		return;
	}

	/* Mark that we were disconnected. */
	ctx->registered = FALSE;

	/* Close the connection, to flush out data. */
	oddjob_dbus_connection_close(ctx->conn);

	/* Unref the old connection. */
	dbus_connection_unref(ctx->conn);

	/* Get a new connection. */
	attempt = 0;
	do {
		dbus_error_init(&err);
		newconn = dbus_bus_get(ctx->bustype, &err);
		if (dbus_error_is_set(&err)) {
			dbus_error_free(&err);
		}
		if ((newconn == NULL) ||
		    (!dbus_connection_get_is_connected(newconn))) {
			/* No joy.  Discard this attempt. */
			if (newconn != NULL) {
				dbus_connection_unref(newconn);
				newconn = NULL;
			}
			/* Wait before trying again. In case it was just a
			 * restart, try to connect N times with our "fast"
			 * timeout, then fall back to the configured timeout. */
			if ((attempt < DEFAULT_FAST_RECONNECT_ATTEMPTS) &&
			    (ctx->reconnect_timeout > DEFAULT_FAST_RECONNECT_TIMEOUT)) {
				sleep(DEFAULT_FAST_RECONNECT_TIMEOUT);
				attempt++;
			} else {
				sleep(ctx->reconnect_timeout);
			}
		}
	} while (newconn == NULL);
	ctx->conn = newconn;

	/* Set our reconnect policy. */
	oddjob_dbus_listener_set_reconnect_timeout(ctx, ctx->reconnect_timeout);

#if 0
	/* According to johnp, we don't need to bother with any of this. */

	/* Request all messages which we're allowed to see. */
	dbus_bus_add_match(ctx->conn, "type='method_call'", &err);
	if (dbus_error_is_set(&err)) {
		/* FIXME: what now? */
		dbus_error_free(&err);
	}
	dbus_bus_add_match(ctx->conn, "type='method_return'", &err);
	if (dbus_error_is_set(&err)) {
		/* FIXME: what now? */
		dbus_error_free(&err);
	}
	dbus_bus_add_match(ctx->conn, "type='error'", &err);
	if (dbus_error_is_set(&err)) {
		/* FIXME: what now? */
		dbus_error_free(&err);
	}
#endif

	/* Re-register our filter, which does the dispatching. */
	ctx->registered = dbus_connection_add_filter(ctx->conn,
						     oddjob_dbus_filter,
						     ctx,
						     NULL);
	if (!ctx->registered) {
		/* FIXME: what if this fails? */;
	}

	/* Attempt to rebind to the service names we had. */
	for (i = 0; i < ctx->n_services; i++) {
		if (!oddjob_dbus_bind(ctx->conn, ctx->services[i].name)) {
			/* FIXME: what if one of these returns FALSE? */;
		}
	}

	/* Get ready to process more messages. */
	mainloop_reinit(ctx->conn);
}

static DBusHandlerResult
oddjob_dbus_filter(DBusConnection *conn, DBusMessage *message, void *user_data)
{
	struct oddjob_dbus_context *ctx;
	struct oddjob_dbus_service *srv;
	struct oddjob_dbus_object *obj;
	struct oddjob_dbus_interface *interface;
	struct oddjob_dbus_message *msg;
	char n_args[LINE_MAX];
	const char *sender_bus_name;
	const char *called_service, *called_path,
		   *called_interface, *called_member;
	unsigned long uid;
	struct passwd *pwd;
	int i, j;

	ctx = user_data;

	/* If it's a global signal, check for disconnect. */
	if (ctx->reconnect_timeout > 0) {
		/* Disconnect from the message bus itself. */
		if (dbus_message_has_sender(message,
					    DBUS_SERVICE_DBUS) &&
		    message_has_path(message, DBUS_PATH_DBUS) &&
		    dbus_message_is_signal(message,
		   			   DBUS_INTERFACE_DBUS,
					   "Disconnected")) {
			return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
		}
		/* Disconnect from the library. */
#if DBUS_CHECK_VERSION(0,30,0)
		if (message_has_path(message, DBUS_PATH_LOCAL) &&
		    dbus_message_is_signal(message,
		   			   DBUS_INTERFACE_LOCAL,
					   "Disconnected")) {
			return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
		}
#elif DBUS_CHECK_VERSION(0,20,0)
		if (message_has_path(message,
				     DBUS_PATH_ORG_FREEDESKTOP_LOCAL) &&
		    dbus_message_is_signal(message,
		   			   DBUS_INTERFACE_ORG_FREEDESKTOP_LOCAL,
					   "Disconnected")) {
			return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
		}
#else
#error "Don't know how to read message data for your version of D-Bus!"
#endif
	}

	/* We only care about method calls to our services, so check that it's a
	 * method call to one of our well-known names. */
	called_service = dbus_message_get_destination(message);
	called_path = dbus_message_get_path(message);
	called_interface = dbus_message_get_interface(message);
	called_member = dbus_message_get_member(message);

	/* Get the called service name and find the service. */
	for (i = 0; (called_service != NULL) && (i < ctx->n_services); i++) {
		if (strcmp(ctx->services[i].name, called_service) == 0) {
			break;
		}
	}
	if (i >= ctx->n_services) {
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	}
	srv = &ctx->services[i];

	/* Check that the message is a method call. */
	if ((called_interface != NULL) && (called_member != NULL)) {
		if (!(dbus_message_is_method_call(message,
						  called_interface,
						  called_member))) {
			return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
		}
	}

	/* Build our stable message structure. */
	msg = oddjob_dbus_message_from_message(conn, message, FALSE, TRUE);
	if (msg == NULL) {
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	}

	/* Find the bus address of the message sender. */
	sender_bus_name = dbus_message_get_sender(message);
	if (sender_bus_name == NULL) {
		oddjob_dbus_send_message_response_error(msg,
							ODDJOB_ERROR_UNKNOWN_SENDER,
							n_args);
		oddjob_dbus_message_free(msg);
		return DBUS_HANDLER_RESULT_HANDLED;
	}

	/* Get the called object path and find the object. */
	for (i = 0; (called_path != NULL) && (i < srv->n_objects); i++) {
		if (fnmatch(srv->objects[i].path, called_path,
			    ODDJOB_OBJECT_FNMATCH_FLAGS) == 0) {
			break;
		}
	}
	if (i >= srv->n_objects) {
		oddjob_dbus_send_message_response_error(msg,
							ODDJOB_ERROR_NO_OBJECT,
							called_path ?
							called_path : "");
		oddjob_dbus_message_free(msg);
		return DBUS_HANDLER_RESULT_HANDLED;
	}
	obj = &srv->objects[i];

	/* Get the called interface and find the interface. */
	for (i = 0;
	     (called_interface != NULL) && (i < obj->n_interfaces);
	     i++) {
		if (strcmp(obj->interfaces[i].interface,
			   called_interface) == 0) {
			break;
		}
	}
	if (i >= obj->n_interfaces) {
		oddjob_dbus_send_message_response_error(msg,
							ODDJOB_ERROR_NO_INTERFACE,
							called_interface ?
							called_interface : "");
		oddjob_dbus_message_free(msg);
		return DBUS_HANDLER_RESULT_HANDLED;
	}
	interface = &obj->interfaces[i];

	/* Search for the method. */
	for (i = 0;
	     (called_member != NULL) && (i < interface->n_methods);
	     i++) {
		if (strcmp(interface->methods[i].method, called_member) == 0) {
			break;
		}
	}
	if (i >= interface->n_methods) {
		oddjob_dbus_send_message_response_error(msg,
							ODDJOB_ERROR_NO_METHOD,
							called_member ?
							called_member : "");
		oddjob_dbus_message_free(msg);
		return DBUS_HANDLER_RESULT_HANDLED;
	}

	/* Check that we actually have a method registered. */
	if (interface->methods[i].handler == NULL) {
		oddjob_dbus_send_message_response_error(msg,
							ODDJOB_ERROR_UNIMPLEMENTED_METHOD,
							called_member ?
							called_member : "");
		oddjob_dbus_message_free(msg);
		return DBUS_HANDLER_RESULT_HANDLED;
	}

	/* Get the UID of the sending user and resolve it to a name. */
	uid = dbus_bus_get_unix_user(conn, sender_bus_name, NULL);
	pwd = getpwuid(uid);
	if ((pwd == NULL) || (pwd->pw_uid != uid)) {
		snprintf(n_args, sizeof(n_args), "UID=%lu", uid);
		oddjob_dbus_send_message_response_error(msg,
							ODDJOB_ERROR_UNKNOWN_USER,
							n_args);
		oddjob_dbus_message_free(msg);
		return DBUS_HANDLER_RESULT_HANDLED;
	}

	/* Check the arguments for verboten chars. */
	for (j = 0; j < msg->n_args; j++) {
		if (strpbrk(msg->args[j], "\r\n") != NULL) {
			break;
		}
	}
	if (j < msg->n_args) {
		oddjob_dbus_send_message_response_error(msg,
							ODDJOB_ERROR_INVALID_CALL,
							"invalid invocation");
		oddjob_dbus_message_free(msg);
		return DBUS_HANDLER_RESULT_HANDLED;
	}

	/* Check the number of arguments. */
	if (msg->n_args != interface->methods[i].n_arguments) {
		snprintf(n_args, sizeof(n_args),
			 "wrong number of arguments: "
			 "expected %d, called with %d",
			 interface->methods[i].n_arguments,
			 msg->n_args);
		oddjob_dbus_send_message_response_error(msg,
							ODDJOB_ERROR_INVALID_CALL,
							n_args);
		oddjob_dbus_message_free(msg);
		return DBUS_HANDLER_RESULT_HANDLED;
	}

	/* Actually call the handler. */
	interface->methods[i].handler(ctx,
				      msg,
				      called_service,
				      called_path,
				      called_interface,
				      called_member,
				      pwd->pw_name,
				      uid,
				      interface->methods[i].data);
	oddjob_dbus_message_free(msg);

	return DBUS_HANDLER_RESULT_HANDLED;
}

dbus_bool_t
oddjob_dbus_listener_add_method(struct oddjob_dbus_context *ctx,
				const char *service_name,
				const char *object_path,
				const char *interface,
				const char *method,
				int n_arguments,
				oddjob_dbus_handler *handler,
				void *data)
{
	int i;
	struct oddjob_dbus_service *srv;
	struct oddjob_dbus_object *obj;
	struct oddjob_dbus_interface *interf;
	struct oddjob_dbus_method *meth;

	/* find the service, creating it if it doesn't already exist. */
	for (i = 0; i < ctx->n_services; i++) {
		if ((ctx->services[i].name != NULL) &&
		    (strcmp(service_name, ctx->services[i].name) == 0)) {
			break;
		}
	}
	if (i >= ctx->n_services) {
		/* Try to set ourselves up with the specified well-known
		 * service name.  If it fails, there may already be another
		 * copy running, but that's not our problem to solve. */
		if (!oddjob_dbus_bind(ctx->conn, service_name)) {
			fprintf(stderr, "Error binding to service name "
				"\"%s\"!\n", service_name);
			return FALSE;
		}
		oddjob_resize_array((void**)&ctx->services,
				    sizeof(ctx->services[0]),
				    ctx->n_services, i + 1);
		ctx->services[i].name = oddjob_strdup(service_name);
		ctx->services[i].objects = NULL;
		ctx->services[i].n_objects = 0;
		ctx->n_services = i + 1;
	}
	srv = &ctx->services[i];

	/* find the object, creating it if it doesn't already exist. */
	for (i = 0; i < srv->n_objects; i++) {
		if ((srv->objects[i].path != NULL) &&
		    (strcmp(object_path, srv->objects[i].path) == 0)) {
			break;
		}
	}
	if (i >= srv->n_objects) {
		oddjob_resize_array((void**)&srv->objects,
				    sizeof(srv->objects[0]),
				    srv->n_objects, i + 1);
		srv->objects[i].path = oddjob_strdup(object_path);
		srv->objects[i].interfaces = NULL;
		srv->objects[i].n_interfaces = 0;
		srv->n_objects = i + 1;
	}
	obj = &srv->objects[i];

	/* find the interface, creating it if it doesn't already exist. */
	for (i = 0; i < obj->n_interfaces; i++) {
		if ((obj->interfaces[i].interface != NULL) &&
		    (strcmp(interface, obj->interfaces[i].interface) == 0)) {
			break;
		}
	}
	if (i >= obj->n_interfaces) {
		oddjob_resize_array((void**)&obj->interfaces,
				    sizeof(obj->interfaces[0]),
				    obj->n_interfaces, i + 1);
		obj->interfaces[i].interface = oddjob_strdup(interface);
		obj->n_interfaces = i + 1;
	}
	interf = &obj->interfaces[i];

	/* find the method, creating it if it doesn't already exist */
	for (i = 0; i < interf->n_methods; i++) {
		if ((interf->methods[i].method != NULL) &&
		    (strcmp(method, interf->methods[i].method) == 0)) {
			break;
		}
	}
	if (i >= interf->n_methods) {
		oddjob_resize_array((void**)&interf->methods,
				    sizeof(interf->methods[0]),
				    interf->n_methods, i + 1);
		interf->methods[i].method = oddjob_strdup(method);
		interf->n_methods = i + 1;
	}

	/* set the method's pointers */
	meth = &interf->methods[i];
	meth->n_arguments = n_arguments;
	meth->handler = handler;
	meth->data = data;

	/* last step - if we haven't added a filter yet, do that */
	if (!ctx->registered) {
		ctx->registered = dbus_connection_add_filter(ctx->conn,
							     oddjob_dbus_filter,
							     ctx,
							     NULL);
							     
	}

	return TRUE;
}

dbus_bool_t
oddjob_dbus_listener_remove_method(struct oddjob_dbus_context *ctx,
				   const char *service_name,
				   const char *object_path,
				   const char *interface,
				   const char *method)
{
	int i;
	struct oddjob_dbus_service *srv;
	struct oddjob_dbus_object *obj;
	struct oddjob_dbus_interface *interf;
	struct oddjob_dbus_method *meth;

	/* find the service */
	srv = NULL;
	for (i = 0; i < ctx->n_services; i++) {
		if ((ctx->services[i].name != NULL) &&
		    (strcmp(service_name, ctx->services[i].name) == 0)) {
			srv = &ctx->services[i];
			break;
		}
	}
	if (srv == NULL) {
		return TRUE;
	}

	/* find the object */
	obj = NULL;
	for (i = 0; i < srv->n_objects; i++) {
		if ((srv->objects[i].path != NULL) &&
		    (strcmp(object_path, srv->objects[i].path) == 0)) {
			obj = &srv->objects[i];
			break;
		}
	}
	if (obj == NULL) {
		return TRUE;
	}

	/* find the interface */
	interf = NULL;
	for (i = 0; i < obj->n_interfaces; i++) {
		if ((obj->interfaces[i].interface != NULL) &&
		    (strcmp(interface, obj->interfaces[i].interface) == 0)) {
			interf = &obj->interfaces[i];
			break;
		}
	}
	if (interf == NULL) {
		return TRUE;
	}

	/* find the method */
	meth = NULL;
	for (i = 0; i < interf->n_methods; i++) {
		if ((interf->methods[i].method != NULL) &&
		    (strcmp(method, interf->methods[i].method) == 0)) {
			meth = &interf->methods[i];
			break;
		}
	}
	if (meth == NULL) {
		return TRUE;
	}

	/* now, if the interface has exactly one method, free it, else just
	 * remove this method from its list */
	oddjob_free(meth->method);
	meth->n_arguments = 0;
	meth->handler = NULL;
	meth->data = NULL;
	if (interf->n_methods > 1) {
		for (i = 0; i < interf->n_methods; i++) {
			if (&interf->methods[i] == meth) {
				memmove(&interf->methods[i],
					&interf->methods[i + 1],
					sizeof(interf->methods[i]) *
					       (interf->n_methods - (i + 1)));
				break;
			}
		}
		oddjob_resize_array((void**)&interf->methods,
				    sizeof(interf->methods[0]),
				    interf->n_methods, interf->n_methods - 1);
		interf->n_methods--;
	} else {
		oddjob_resize_array((void**)&interf->methods,
				    sizeof(interf->methods[0]),
				    interf->n_methods, 0);
		interf->n_methods = 0;
	}

	/* if this interface still has methods, we're done */
	if (interf->n_methods > 0) {
		return TRUE;
	}

	/* now, if the object has exactly one interface, free it, else just
	 * remove this interface from its list */
	oddjob_free(interf->interface);
	if (obj->n_interfaces > 1) {
		for (i = 0; i < obj->n_interfaces; i++) {
			if (&obj->interfaces[i] == interf) {
				memmove(&obj->interfaces[i],
					&obj->interfaces[i + 1],
					sizeof(obj->interfaces[i]) *
					       (obj->n_interfaces - (i + 1)));
				break;
			}
		}
		oddjob_resize_array((void**)&obj->interfaces,
				    sizeof(obj->interfaces[0]),
				    obj->n_interfaces, obj->n_interfaces - 1);
		obj->n_interfaces--;
	} else {
		oddjob_resize_array((void**)&obj->interfaces,
				    sizeof(obj->interfaces[0]),
				    obj->n_interfaces, 0);
		obj->n_interfaces = 0;
	}

	/* if this object still has interfaces, then we're done */
	if (obj->n_interfaces > 0) {
		return TRUE;
	}

	/* now, if the service has exactly one object, free it, else just
	 * remove this object from its list */
	oddjob_free(obj->path);
	if (srv->n_objects > 1) {
		for (i = 0; i < srv->n_objects; i++) {
			if (&srv->objects[i] == obj) {
				memmove(&srv->objects[i],
					&srv->objects[i + 1],
					sizeof(srv->objects[i]) *
					       (srv->n_objects - (i + 1)));
				break;
			}
		}
		oddjob_resize_array((void**)&srv->objects,
				    sizeof(srv->objects[0]),
				    srv->n_objects, srv->n_objects - 1);
		srv->n_objects--;
	} else {
		oddjob_resize_array((void**)&srv->objects,
				    sizeof(srv->objects[0]),
				    srv->n_objects, 0);
		srv->n_objects = 0;
	}

	/* if this service still has objects, we're done */
	if (srv->n_objects > 0) {
		return TRUE;
	}

	/* now, unbind from the service. if the listener has exactly one
	 * service, free it, else just remove this service from its list */
	oddjob_dbus_unbind(ctx->conn, srv->name);
	oddjob_free(srv->name);
	if (ctx->n_services > 1) {
		for (i = 0; i < ctx->n_services; i++) {
			if (&ctx->services[i] == srv) {
				memmove(&ctx->services[i],
					&ctx->services[i + 1],
					sizeof(ctx->services[i]) *
					       (ctx->n_services - (i + 1)));
				break;
			}
		}
		oddjob_resize_array((void**)&ctx->services,
				    sizeof(ctx->services[0]),
				    srv->n_objects, srv->n_objects - 1);
		srv->n_objects--;
	} else {
		oddjob_resize_array((void**)&ctx->services,
				    sizeof(ctx->services[0]),
				    srv->n_objects, 0);
		ctx->n_services = 0;
	}

	/* if this listener still has services, we're done */
	if (ctx->n_services > 0) {
		return TRUE;
	}

	/* last step - if we have no services, remove the filter */
	if (ctx->registered) {
		dbus_connection_remove_filter(ctx->conn,
					      oddjob_dbus_filter,
					      ctx);
		ctx->registered = FALSE;
	}

	return TRUE;
}

int
oddjob_dbus_message_get_n_args(struct oddjob_dbus_message *msg)
{
	return msg->n_args;
}

const char *
oddjob_dbus_message_get_arg(struct oddjob_dbus_message *msg, int n)
{
	if (n >= msg->n_args) {
		return NULL;
	}
	return msg->args[n];
}

void
oddjob_dbus_send_introspection_text(struct oddjob_dbus_message *msg,
				    const char *text)
{
	DBusMessage *message;
	const char *empty = "";

	message = dbus_message_new_method_return(msg->msg);
#if DBUS_CHECK_VERSION(0,30,0)
	dbus_message_append_args(message,
				 DBUS_TYPE_STRING, text ? &text : &empty,
				 DBUS_TYPE_INVALID);
#elif DBUS_CHECK_VERSION(0,20,0)
	dbus_message_append_args(message,
				 DBUS_TYPE_STRING, text ? text : empty,
				 DBUS_TYPE_INVALID);
#else
#error	"Don't know how to set message arguments with your version of D-Bus!"
#endif
	dbus_connection_send(msg->conn, message, NULL);
	dbus_message_unref(message);
}

void
oddjob_dbus_send_message_response_text(struct oddjob_dbus_message *msg,
				       int result_code,
				       const char *text)
{
	DBusMessage *message;
	const char *empty = "";
	int32_t result;

	message = dbus_message_new_method_return(msg->msg);
	result = result_code;
#if DBUS_CHECK_VERSION(0,30,0)
	dbus_message_append_args(message,
				 DBUS_TYPE_INT32, &result,
				 DBUS_TYPE_INVALID);
#else
	dbus_message_append_args(message,
				 DBUS_TYPE_INT32, result,
				 DBUS_TYPE_INVALID);
#endif
#if DBUS_CHECK_VERSION(0,30,0)
	dbus_message_append_args(message,
				 DBUS_TYPE_STRING, text ? &text : &empty,
				 DBUS_TYPE_INVALID);
#elif DBUS_CHECK_VERSION(0,20,0)
	dbus_message_append_args(message,
				 DBUS_TYPE_STRING, text ? text : empty,
				 DBUS_TYPE_INVALID);
#else
#error	"Don't know how to set message arguments with your version of D-Bus!"
#endif
#if DBUS_CHECK_VERSION(0,30,0)
	dbus_message_append_args(message,
				 DBUS_TYPE_STRING, &empty,
				 DBUS_TYPE_INVALID);
#elif DBUS_CHECK_VERSION(0,20,0)
	dbus_message_append_args(message,
				 DBUS_TYPE_STRING, empty,
				 DBUS_TYPE_INVALID);
#else
#error	"Don't know how to set message arguments with your version of D-Bus!"
#endif
	dbus_connection_send(msg->conn, message, NULL);
	dbus_message_unref(message);
}

void
oddjob_dbus_send_message_response_success(struct oddjob_dbus_message *msg,
					  int result_code,
					  struct oddjob_buffer *outc,
					  struct oddjob_buffer *errc)
{
	DBusMessage *message;
	const char *p;
	int32_t result;

	message = dbus_message_new_method_return(msg->msg);
	result = result_code;
#if DBUS_CHECK_VERSION(0,30,0)
	dbus_message_append_args(message,
				 DBUS_TYPE_INT32, &result,
				 DBUS_TYPE_INVALID);
#else
	dbus_message_append_args(message,
				 DBUS_TYPE_INT32, result,
				 DBUS_TYPE_INVALID);
#endif
	if ((oddjob_buffer_length(outc) > 0) &&
	    (oddjob_buffer_data(outc)[oddjob_buffer_length(outc)] != '\0')) {
		abort();
	}
#if DBUS_CHECK_VERSION(0,30,0)
	p = (const char *) oddjob_buffer_data(outc);
	dbus_message_append_args(message,
				 DBUS_TYPE_STRING, &p,
				 DBUS_TYPE_INVALID);
	p = (const char *) oddjob_buffer_data(errc);
	dbus_message_append_args(message,
				 DBUS_TYPE_STRING, &p,
				 DBUS_TYPE_INVALID);
#elif DBUS_CHECK_VERSION(0,20,0)
	p = (const char *) oddjob_buffer_data(outc);
	dbus_message_append_args(message,
				 DBUS_TYPE_STRING, p,
				 DBUS_TYPE_INVALID);
	p = (const char *) oddjob_buffer_data(errc);
	dbus_message_append_args(message,
				 DBUS_TYPE_STRING, p,
				 DBUS_TYPE_INVALID);
#else
#error	"Don't know how to set message arguments with your version of D-Bus!"
#endif
	dbus_connection_send(msg->conn, message, NULL);
	dbus_message_unref(message);
}

void
oddjob_dbus_send_message_response_error(struct oddjob_dbus_message *msg,
				        const char *error,
				        const char *text)
{
	DBusMessage *message;
	message = dbus_message_new_error(msg->msg, error, text);
	dbus_connection_send(msg->conn, message, NULL);
	dbus_message_unref(message);
}

int
oddjob_dbus_call_bus_methodv(DBusBusType bus,
			     const char *service, const char *object_path,
			     const char *interface, const char *method,
			     int *result,
			     char *output, size_t output_length,
			     char *error, size_t error_length,
			     char **argv)
{
	DBusConnection *conn;
	DBusMessage *message, *reply;
	DBusError err;
	struct oddjob_dbus_message *msg;
	int ret, i;
	const char *p;

	if (output != NULL) {
		memset(output, '\0', output_length);
	}

	memset(&err, 0, sizeof(err));
	dbus_error_init(&err);
	conn = dbus_bus_get(bus, &err);
	if (conn == NULL) {
		if (dbus_error_is_set(&err) && (output != NULL)) {
			snprintf(output, output_length, "%s: %s",
				 err.name, err.message);
		}
		dbus_error_free(&err);
		return -2;
	}

	dbus_connection_ref(conn);
	message = dbus_message_new_method_call(service,
					       object_path,
					       interface,
					       method);
	for (i = 0; (argv != NULL) && (argv[i] != NULL); i++) {
		p = argv[i];
#if DBUS_CHECK_VERSION(0,30,0)
		dbus_message_append_args(message,
					 DBUS_TYPE_STRING, &p,
					 DBUS_TYPE_INVALID);
#elif DBUS_CHECK_VERSION(0,20,0)
		dbus_message_append_args(message,
					 DBUS_TYPE_STRING, p,
					 DBUS_TYPE_INVALID);
#else
#error		"Don't know how to set message arguments with your version of D-Bus!"
#endif
	}
	reply = dbus_connection_send_with_reply_and_block(conn, message,
							  -1, &err);
	msg = oddjob_dbus_message_from_message(conn, reply, TRUE, FALSE);
	if (result) {
		*result = msg->result;
	}
	if (output_length > 0) {
		memset(output, '\0', output_length);
		if (msg->n_args > 0) {
			strncpy(output, msg->args[0], output_length - 1);
		}
	}
	if (error_length > 0) {
		memset(error, '\0', error_length);
		if (msg->n_args > 1) {
			strncpy(error, msg->args[1], error_length - 1);
		}
	}

	if (dbus_error_is_set(&err)) {
		if (output != NULL) {
			snprintf(output, output_length, "%s: %s",
				 err.name, err.message);
		}
		if (error != NULL) {
			snprintf(error, error_length, "%s: %s",
				 err.name, err.message);
		}
		dbus_error_free(&err);
		ret = -1;
	} else {
		ret = 0;
	}

	oddjob_dbus_message_free(msg);

	if (reply != NULL) {
		dbus_message_unref(reply);
	}

	dbus_message_unref(message);
	dbus_connection_unref(conn);

	return ret;
}

int
oddjob_dbus_call_method(DBusBusType bus,
			const char *service, const char *object_path,
			const char *interface, const char *method,
			int *result,
			char *output, size_t output_length,
			char *error, size_t error_length,
			...)
{
	va_list ap;
	char **argv;
	char *p;
	int i;

	argv = NULL;
	i = 0;
	va_start(ap, error_length);
	while ((p = va_arg(ap, char*)) != NULL) {
		oddjob_resize_array((void **) &argv, sizeof(char*), i, i + 2);
		argv[i] = p;
		i++;
	}
	va_end(ap);
	i = oddjob_dbus_call_bus_methodv(bus,
					 service, object_path,
					 interface, method,
				         result,
				         output, output_length,
				         error, error_length,
				         argv);
	oddjob_free(argv);
	return i;
}

void
oddjob_dbus_main_init(struct oddjob_dbus_context *ctx)
{
	mainloop_reset_signal_handlers();
	mainloop_init(ctx->conn);
}

void
oddjob_dbus_main_done(struct oddjob_dbus_context *ctx)
{
	mainloop_done(ctx->conn);
}

int
oddjob_dbus_main_iterate(struct oddjob_dbus_context *ctx)
{
	return mainloop_iterate(ctx->conn);
}

const char *
oddjob_dbus_get_default_service(void)
{
	return ODDJOB_NAMESPACE "." PACKAGE_NAME;
}

const char *
oddjob_dbus_get_default_object(void)
{
	return ODDJOB_NAMESPACE_PATH "/" PACKAGE_NAME;
}

const char *
oddjob_dbus_get_default_interface(void)
{
	return ODDJOB_NAMESPACE "." PACKAGE_NAME;
}
