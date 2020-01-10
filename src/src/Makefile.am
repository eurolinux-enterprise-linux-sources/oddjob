EXTRA_DIST = oddjob.conf.in oddjob.pc.in \
	eightx.sh \
	tenx.sh \
	exit1.sh \
	printenv.sh.in \
	sanity.sh \
	sigint.sh \
	sleep30.sh

AM_CFLAGS = @DBUS_CFLAGS@ @XML_CFLAGS@ @SELINUX_CFLAGS@
bin_PROGRAMS = oddjob_request
sbin_PROGRAMS = oddjobd
sysconf_DATA = oddjobd.conf

man_MANS = oddjob_request.1 oddjob.conf.5 oddjobd.conf.5 oddjobd.8
if BUILD_PAM
man_MANS += pam_oddjob_mkhomedir.8
endif

confddir = $(sysconfdir)/$(PACKAGE)d.conf.d
confd_DATA = oddjobd-introspection.conf
if BUILD_PAM
confd_DATA += oddjobd-mkhomedir.conf
endif

CLEANFILES = $(confd_DATA)

oddjobd-introspection.conf: make-i11nconf.sh
	$(SHELL) make-i11nconf.sh > $@

install-data-hook:
	$(INSTALL) -d -m755 $(DESTDIR)/$(sysconfdir)/$(PACKAGE)

pkgsysconfdir = $(sysconfdir)/$(PACKAGE)
systemdbusdir = $(sysconfdir)/@DBUS_PACKAGE@/system.d
systemdbus_DATA = oddjob.conf
if BUILD_PAM
systemdbus_DATA += oddjob-mkhomedir.conf
pkglibexec_PROGRAMS = mkhomedir
endif

pkglibexecdir = $(libexecdir)/$(PACKAGE)
pkglibexec_SCRIPTS = sanity.sh
noinst_SCRIPTS = mkhomedirfor mkmyhomedir reload

if BUILD_PAM
libsecuritydir = $(libdir)/security
libsecurity_LTLIBRARIES = pam_oddjob_mkhomedir.la
endif

lib_LTLIBRARIES =
noinst_LTLIBRARIES =
pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA =
noinst_DATA =
if LIBODDJOB
pkginclude_HEADERS = oddjob.h
lib_LTLIBRARIES += liboddjob.la
pkgconfig_DATA += oddjob.pc
else
noinst_HEADERS = oddjob.h
noinst_LTLIBRARIES += liboddjob.la
noinst_DATA += oddjob.pc
endif

noinst_LTLIBRARIES += liboddcommon.la libodddbus.la liboddselinux.la
liboddjob_la_SOURCES = \
	common.h \
	buffer.c buffer.h \
	util.h util.c \
	oddjob_dbus.h oddjob_dbus.c \
	mainloop.h mainloop.c
liboddcommon_la_SOURCES = \
	buffer.c buffer.h \
	util.c \
	util.h \
	common.h
libodddbus_la_SOURCES = \
	oddjob_dbus.c \
	oddjob_dbus.h \
	mainloop.c \
	mainloop.h \
	common.h
liboddselinux_la_SOURCES = \
	selinux.h \
	selinux.c \
	common.h

mkhomedir_SOURCES = \
	common.h \
	handlers.h \
	selinux.h \
	mkhomedir.c
mkhomedir_LDADD = liboddcommon.la liboddselinux.la @SELINUX_LIBS@

pam_oddjob_mkhomedir_la_SOURCES = \
	common.h \
	oddjob_dbus.c \
	oddjob_dbus.h \
	mainloop.c \
	mainloop.h \
	pam_oddjob_mkhomedir.c
pam_oddjob_mkhomedir_la_LIBADD = liboddcommon.la @DBUS_LIBS@ @PAM_LIBS@
pam_oddjob_mkhomedir_la_LDFLAGS = -module -avoid-version -export-symbols-regex "pam_sm_.*"

oddjob_request_SOURCES = \
	common.h \
	oddjob_request.c
oddjob_request_LDADD = liboddjob.la @DBUS_LIBS@

oddjobd_SOURCES = \
	common.h \
	handlers.h \
	util.h \
	oddjobd.c
oddjobd_LDADD = libodddbus.la liboddselinux.la liboddcommon.la @DBUS_LIBS@ @XML_LIBS@ @SELINUX_LIBS@
