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
#include <sys/time.h>
#include <sys/wait.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <dbus/dbus.h>
#include "common.h"
#include "mainloop.h"
#include "util.h"

/* Our partial approximation of a main loop, for use by D-Bus.  It's enough
 * for our purposes, at least. */
static struct watch_list {
	enum watch_type { watch_dbus, watch_oddjob } type;
	DBusWatch *dwatch;
	struct OddjobWatch {
		int fd;
		DBusWatchFlags flags;
		OddjobWatchFn *fn;
		void *data;
	} owatch;
	struct watch_list *next;
} *watch_list;

static struct timeout_list {
	enum timeout_type { timeout_dbus } type;
	DBusTimeout *dtimeout;
	struct timeval start;
	struct timeout_list *next;
} *timeout_list;

static struct pid_list {
	pid_t pid;
	OddjobPidFn *fn;
	void *data;
	struct pid_list *next;
} *pid_list;

dbus_bool_t
mainloop_pid_add(pid_t pid, OddjobPidFn *fn, void *data)
{
	struct pid_list *l;
	for (l = pid_list; l != NULL; l = l->next) {
		if (l->pid == pid) {
			return TRUE;
		}
	}
	l = malloc(sizeof(struct pid_list));
	if (l == NULL) {
		return FALSE;
	}
	memset(l, 0, sizeof(*l));
	l->pid = pid;
	l->fn = fn;
	l->data = data;
	l->next = pid_list;
	pid_list = l;
	return TRUE;
}

void
mainloop_pid_remove(pid_t pid)
{
	struct pid_list *l, *pred;
	for (l = pid_list, pred = NULL; l != NULL; l = l->next) {
		if (l->pid == pid) {
			if (pred == NULL) {
				pid_list = l->next;
				free(l);
			} else {
				pred->next = l->next;
				free(l);
			}
			break;
		}
		pred = l;
	}
}

dbus_bool_t
mainloop_oddjob_watch_add(int fd, DBusWatchFlags flags,
			  OddjobWatchFn *fn, void *data)
{
	struct watch_list *l;
	for (l = watch_list; l != NULL; l = l->next) {
		if ((l->type == watch_oddjob) &&
		    (l->owatch.fd == fd)) {
			return TRUE;
		}
	}
	l = malloc(sizeof(struct watch_list));
	if (l == NULL) {
		return FALSE;
	}
	memset(l, 0, sizeof(*l));
	l->type = watch_oddjob;
	l->owatch.fd = fd;
	l->owatch.flags = flags;
	l->owatch.fn = fn;
	l->owatch.data = data;
	l->next = watch_list;
	watch_list = l;
	return TRUE;
}

void
mainloop_oddjob_watch_remove(int fd, DBusWatchFlags unused_flags)
{
	struct watch_list *l, *pred;
	for (l = watch_list, pred = NULL; l != NULL; l = l->next) {
		if ((l->type == watch_oddjob) &&
		    (l->owatch.fd == fd)) {
			if (pred == NULL) {
				watch_list = l->next;
				l->owatch.fd = -1;
				l->next = NULL;
				memset(l, 0, sizeof(*l));
				oddjob_free(l);
			} else {
				pred->next = l->next;
				l->owatch.fd = -1;
				l->next = NULL;
				memset(l, 0, sizeof(*l));
				oddjob_free(l);
			}
			break;
		}
		pred = l;
	}
}

/* Add a watch item to the list.  If it's already there, don't add it again. */
static dbus_bool_t
watch_dbus_add(DBusWatch *watch, void *unused_data)
{
	struct watch_list *l;
	for (l = watch_list; l != NULL; l = l->next) {
		if ((l->type == watch_dbus) && (l->dwatch == watch)) {
			return TRUE;
		}
	}
	l = malloc(sizeof(struct watch_list));
	if (l == NULL) {
		return FALSE;
	}
	memset(l, 0, sizeof(*l));
	l->type = watch_dbus;
	l->dwatch = watch;
	l->next = watch_list;
	watch_list = l;
	return TRUE;
}

/* Remove a watch item from the list. */
static void
watch_dbus_remove(DBusWatch *watch, void *unused_data)
{
	struct watch_list *l, *pred;
	for (l = watch_list, pred = NULL; l != NULL; l = l->next) {
		if ((l->type == watch_dbus) && (l->dwatch == watch)) {
			l->dwatch = NULL;
			if (pred == NULL) {
				watch_list = l->next;
				l->next = NULL;
				memset(l, 0, sizeof(*l));
				oddjob_free(l);
			} else {
				pred->next = l->next;
				l->next = NULL;
				memset(l, 0, sizeof(*l));
				oddjob_free(l);
			}
			break;
		}
		pred = l;
	}
}

/* Toggle whether or not a watch item is enabled. */
static void
watch_dbus_toggle(DBusWatch *unused_watch, void *unused_data)
{
}

/* Add a timeout item to the timeout list. */
static dbus_bool_t
timeout_dbus_add(DBusTimeout *timeout, void *unused_data)
{
	struct timeout_list *l;
	struct timeval tv;
	for (l = timeout_list; l != NULL; l = l->next) {
		if ((l->type == timeout_dbus) && (l->dtimeout == timeout)) {
			return TRUE;
		}
	}
	if (gettimeofday(&tv, NULL) == -1) {
		/* aargh! */
		return FALSE;
	}
	l = malloc(sizeof(struct timeout_list));
	if (l == NULL) {
		return FALSE;
	}
	memset(l, 0, sizeof(*l));
	l->type = timeout_dbus;
	l->dtimeout = timeout;
	memcpy(&l->start, &tv, sizeof(l->start));
	l->next = timeout_list;
	timeout_list = l;
	return TRUE;
}

/* Remove a timeout item from the timeout list. */
static void
timeout_dbus_remove(DBusTimeout *timeout, void *unused_data)
{
	struct timeout_list *l, *pred;
	for (l = timeout_list, pred = NULL; l != NULL; l = l->next) {
		if ((l->type == timeout_dbus) && (l->dtimeout == timeout)) {
			if (pred == NULL) {
				timeout_list = l->next;
				memset(l, 0, sizeof(*l));
				oddjob_free(l);
			} else {
				pred->next = l->next;
				memset(l, 0, sizeof(*l));
				oddjob_free(l);
			}
			break;
		}
		pred = l;
	}
}

/* Toggle whether or not a timeout is enabled. */
static void
timeout_dbus_toggle(DBusTimeout *unused_timeout, void *unused_data)
{
}

/* Set up arguments for select() using data from the watch and timeout lists. */
static void
prepare(int *maxfd, fd_set *rfds, fd_set *wfds, fd_set *efds,
	dbus_bool_t *use_tv, struct timeval *tv)
{
	struct watch_list *wl;
	struct timeout_list *tl;
	int fd, current_interval, this_interval;
	DBusWatchFlags flags;
	struct timeval now;

	FD_ZERO(rfds);
	FD_ZERO(wfds);
	FD_ZERO(efds);
	wl = watch_list;
	*maxfd = -1;
	while (wl != NULL) {
		switch (wl->type) {
		case watch_dbus:
			if (dbus_watch_get_enabled(wl->dwatch)) {
#if DBUS_CHECK_VERSION(1,1,0)
				fd = dbus_watch_get_unix_fd(wl->dwatch);
#else
				fd = dbus_watch_get_fd(wl->dwatch);
#endif
				flags = dbus_watch_get_flags(wl->dwatch);
				if (flags & (DBUS_WATCH_READABLE |
					     DBUS_WATCH_HANGUP)) {
					FD_SET(fd, rfds);
					*maxfd = (*maxfd > fd ? *maxfd : fd);
				}
				if (flags & DBUS_WATCH_WRITABLE) {
					FD_SET(fd, wfds);
					*maxfd = (*maxfd > fd ? *maxfd : fd);
				}
				if (flags & DBUS_WATCH_ERROR) {
					FD_SET(fd, efds);
					*maxfd = (*maxfd > fd ? *maxfd : fd);
				}
			}
			break;
		case watch_oddjob:
			if (wl->owatch.flags & (DBUS_WATCH_READABLE |
						DBUS_WATCH_HANGUP)) {
				FD_SET(wl->owatch.fd, rfds);
				*maxfd = (*maxfd > wl->owatch.fd ?
					  *maxfd :
					  wl->owatch.fd);
			}
			if (wl->owatch.flags & DBUS_WATCH_WRITABLE) {
				FD_SET(wl->owatch.fd, wfds);
				*maxfd = (*maxfd > wl->owatch.fd ?
					  *maxfd :
					  wl->owatch.fd);
			}
			if (wl->owatch.flags & DBUS_WATCH_ERROR) {
				FD_SET(wl->owatch.fd, efds);
				*maxfd = (*maxfd > wl->owatch.fd ?
					  *maxfd :
					  wl->owatch.fd);
			}
		default:
			break;
		}
		wl = wl->next;
	}
	*use_tv = FALSE;
	memset(tv, 0, sizeof(*tv));
	if (pid_list != NULL) {
		*use_tv = TRUE;
		tv->tv_sec = 1;
	}
	tl = timeout_list;
	while (tl != NULL) {
		if (gettimeofday(&now, NULL) == 0) {
			*use_tv = TRUE;
		}
		if (!*use_tv) {
			break;
		}
		switch (tl->type) {
		case timeout_dbus:
			if (dbus_timeout_get_enabled(tl->dtimeout)) {
				current_interval = tv->tv_sec * 1000 +
						   tv->tv_usec / 1000;
				this_interval = dbus_timeout_get_interval(tl->dtimeout);
				this_interval -= 1000 *
						(now.tv_sec - tl->start.tv_sec);

				if ((tl == timeout_list) ||
				    (this_interval < current_interval)) {
					tv->tv_sec = this_interval / 1000;
					tv->tv_usec = (this_interval % 1000) * 1000;
				}
			}
			break;
		default:
			break;
		}
		tl = tl->next;
	}
}

/* For each descriptor with its bit set in one of the fd_set items, call
 * dbus_watch_handle with the right flag to process any pending I/O. */
static void
handle(fd_set *rfds, fd_set *wfds, fd_set *efds, struct timeval *unused_tv)
{
	struct watch_list *wl, *wlnext;
	struct timeout_list *tl, *tlnext;
	struct pid_list *pl, *plnext, *pred;
	int fd;
	unsigned int i;
	DBusWatch *dwatch;
	DBusTimeout *dtimeout;
	DBusWatchFlags  flags;
	struct {
		DBusWatch *watch;
		DBusWatchFlags flags;
	} *dwatches;
	size_t dwatch_count;

	wl = watch_list;
	fd = -1;
	dwatches = NULL;
	dwatch_count = 0;
	while (wl != NULL) {
		wlnext = wl->next;
		switch (wl->type) {
		case watch_dbus:
			dwatch = wl->dwatch;
			if (dbus_watch_get_enabled(dwatch)) {
#if DBUS_CHECK_VERSION(1,1,0)
				fd = dbus_watch_get_unix_fd(dwatch);
#else
				fd = dbus_watch_get_fd(dwatch);
#endif
				flags = 0;
				if (FD_ISSET(fd, rfds)) {
					flags |= DBUS_WATCH_READABLE;
				}
				if (FD_ISSET(fd, wfds)) {
					flags |= DBUS_WATCH_WRITABLE;
				}
				if (FD_ISSET(fd, efds)) {
					flags |= DBUS_WATCH_ERROR;
				}
				if (flags != 0) {
					for (i = 0; i < dwatch_count; i++) {
						if (dwatches[i].watch == dwatch) {
							dwatches[i].flags |= flags;
							break;
						}
					}
					if (i >= dwatch_count) {
						oddjob_resize_array((void **)&dwatches,
								    sizeof(dwatches[0]),
								    dwatch_count,
								    i + 1);
						dwatches[i].watch = dwatch;
						dwatches[i].flags = flags;
						dwatch_count = i + 1;
					}
				}
			}
			break;
		case watch_oddjob:
			flags = 0;
			if (FD_ISSET(wl->owatch.fd, rfds)) {
				flags |= DBUS_WATCH_READABLE;
			}
			if (FD_ISSET(wl->owatch.fd, wfds)) {
				flags |= DBUS_WATCH_WRITABLE;
			}
			if (FD_ISSET(wl->owatch.fd, efds)) {
				flags |= DBUS_WATCH_ERROR;
			}
			if (flags != 0) {
				if (wl->owatch.fn(wl->owatch.fd, flags,
						  wl->owatch.data)) {
					mainloop_oddjob_watch_remove(wl->owatch.fd,
								     wl->owatch.flags);
				}
			}
			break;
		}
		wl = wlnext;
	}
	for (i = 0; i < dwatch_count; i++) {
		dbus_watch_handle(dwatches[i].watch, dwatches[i].flags);
	}
	oddjob_free(dwatches);
	/* PROBABLY WRONG */
	if (fd != -1) {
		tl = timeout_list;
		while (tl != NULL) {
			tlnext = tl->next;
			switch (tl->type) {
			case timeout_dbus:
				dtimeout = tl->dtimeout;
				if (dbus_timeout_get_enabled(dtimeout)) {
					dbus_timeout_handle(dtimeout);
				}
				break;
			}
			tl = tlnext;
		}
	}
	pl = pid_list;
	pred = NULL;
	while (pl != NULL) {
		int status;
		plnext = pl->next;
		if (waitpid(pl->pid, &status, WNOHANG) == pl->pid) {
			pl->fn(pl->pid, status, pl->data);
			mainloop_pid_remove(pl->pid);
		}
		pl = plnext;
	}
}

/* Connect our callbacks for the D-Bus connection. */
void
mainloop_reinit(DBusConnection *conn)
{
	dbus_connection_set_watch_functions(conn,
					    watch_dbus_add,
					    watch_dbus_remove,
					    watch_dbus_toggle,
					    NULL,
					    NULL);
	dbus_connection_set_timeout_functions(conn,
					      timeout_dbus_add,
					      timeout_dbus_remove,
					      timeout_dbus_toggle,
					      NULL,
					      NULL);
}

void
mainloop_init(DBusConnection *conn)
{
	mainloop_reinit(conn);
}

void
mainloop_done(DBusConnection *conn)
{
	dbus_connection_set_watch_functions(conn,
					    NULL,
					    NULL,
					    NULL,
					    NULL,
					    NULL);
	dbus_connection_set_timeout_functions(conn,
					      NULL,
					      NULL,
					      NULL,
					      NULL,
					      NULL);
}

/* Process I/O for the connection, dispatch messages, and then flush any
 * pending output.  Return the number of descriptors which we serviced.  Note
 * that if we got a timeout, 0 is a *successful* return code. */
int
mainloop_iterate(DBusConnection *conn)
{
	int i, max_fd;
	dbus_bool_t use_tv;
	fd_set rfds, efds, wfds;
	struct timeval tv;

	prepare(&max_fd, &rfds, &wfds, &efds, &use_tv, &tv);
	i = select(max_fd + 1, &rfds, &wfds, &efds, use_tv ? &tv : NULL);
	if (i != -1) {
		handle(&rfds, &wfds, &efds, &tv);
		while (dbus_connection_get_dispatch_status(conn) ==
		       DBUS_DISPATCH_DATA_REMAINS) {
			dbus_connection_dispatch(conn);
		}
#if DBUS_CHECK_VERSION(0,30,0)
		while (dbus_connection_has_messages_to_send(conn)) {
			dbus_connection_flush(conn);
		}
#elif DBUS_CHECK_VERSION(0,20,0)
		while (dbus_connection_get_outgoing_size(conn) > 0) {
			dbus_connection_flush(conn);
		}
#else
#error "Don't know how to check if messages need to be flushed!"
#endif
	}
	return i;
}

/* Set the handler for an arbitrary set of signals to SIG_DFL. */
void
mainloop_reset_signal_handlers(void)
{
#ifdef SIGALRM
	signal(SIGALRM, SIG_DFL);
#endif
#ifdef SIGINT
	signal(SIGINT, SIG_DFL);
#endif
#ifdef SIGQUIT
	signal(SIGQUIT, SIG_DFL);
#endif
#ifdef SIGILL
	signal(SIGILL, SIG_DFL);
#endif
#ifdef SIGABRT
	signal(SIGABRT, SIG_DFL);
#endif
#ifdef SIGKILL
	signal(SIGKILL, SIG_DFL);
#endif
#ifdef SIGSEGV
	signal(SIGSEGV, SIG_DFL);
#endif
#ifdef SIGPIPE
	signal(SIGPIPE, SIG_IGN);
#endif
#ifdef SIGTERM
	signal(SIGTERM, SIG_DFL);
#endif
#ifdef SIGCHLD
	signal(SIGCHLD, SIG_DFL);
#endif
#ifdef SIGCONT
	signal(SIGCONT, SIG_DFL);
#endif
#ifdef SIGSTOP
	signal(SIGSTOP, SIG_DFL);
#endif
}
