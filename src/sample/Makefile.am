EXTRA_DIST = \
	$(PACKAGE)d-sample.conf.in \
	$(PACKAGE)-sample.conf \
	$(PACKAGE)-sample.sh

daemonconfdir = $(sysconfdir)/$(PACKAGE)d.conf.d
systemdbusdir = $(sysconfdir)/@DBUS_PACKAGE@/system.d
pkglibexecdir = $(libexecdir)/$(PACKAGE)

if INSTALL_SAMPLE
daemonconf_DATA = $(PACKAGE)d-sample.conf
systemdbus_DATA = $(PACKAGE)-sample.conf
pkglibexec_SCRIPTS = $(PACKAGE)-sample.sh
endif
