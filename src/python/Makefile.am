EXTRA_DIST = sample.py
if PYTHON
PYTHON_INCLUDES = `$(PYTHON) -c "from distutils import sysconfig; print sysconfig.get_python_inc();"`
AM_CFLAGS = -I$(PYTHON_INCLUDES) @DBUS_CFLAGS@
pyexec_LTLIBRARIES = @PACKAGE_NAME@module.la
@PACKAGE_NAME@module_la_LDFLAGS = -module -avoid-version --export-symbol-regex init@PACKAGE_NAME@
@PACKAGE_NAME@module_la_SOURCES = oddjobmodule.c
@PACKAGE_NAME@module_la_LIBADD = \
	../src/mainloop.lo \
	../src/util.lo \
	../src/oddjob_dbus.lo \
	@DBUS_LIBS@
endif
