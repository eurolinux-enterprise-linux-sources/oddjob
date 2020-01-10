AC_INIT(oddjob,0.30)
AC_PREREQ(2.59)
PACKAGE_NAME_CAPS=`echo $PACKAGE_NAME | tr '[a-z]' '[A-Z]'`
AC_DEFINE_UNQUOTED(PACKAGE_NAME_CAPS,"$PACKAGE_NAME_CAPS",[Define to the package name, in caps.])
AC_SUBST(PACKAGE_NAME_CAPS)
AM_INIT_AUTOMAKE([foreign])
AC_PROG_CC
AM_MAINTAINER_MODE

AC_DEFINE(_GNU_SOURCE,1,[Use GNU libc extensions.])

AC_PROG_LIBTOOL

DBUS_PACKAGE=dbus-1
PKG_CHECK_MODULES(DBUS,$DBUS_PACKAGE)
PKG_CHECK_MODULES(XML,libxml-2.0)

AC_MSG_CHECKING([D-BUS version])
DBUS_VERSION=`pkg-config --modversion $DBUS_PACKAGE`
DBUS_PREFIX=`pkg-config --modversion $DBUS_PACKAGE`
DBUS_MAJOR_VERSION=`echo $DBUS_VERSION | cut -f1 -d.`
DBUS_MINOR_VERSION=`echo $DBUS_VERSION | cut -f2 -d.`
DBUS_MICRO_VERSION=`echo $DBUS_VERSION | cut -f3 -d.`
if test x$DBUS_MAJOR_VERSION = x ; then
	DBUS_MAJOR_VERSION=0
fi
if test x$DBUS_MINOR_VERSION = x ; then
	DBUS_MINOR_VERSION=0
fi
if test x$DBUS_MICRO_VERSION = x ; then
	DBUS_MICRO_VERSION=0
fi
AC_MSG_RESULT([pkg-config reports $DBUS_VERSION, treating as ${DBUS_MAJOR_VERSION}.${DBUS_MINOR_VERSION}.${DBUS_MICRO_VERSION}])
AC_DEFINE_UNQUOTED(ODDJOB_DBUS_MAJOR_VERSION,$DBUS_MAJOR_VERSION,[Define to the major version of D-BUS with which oddjob is being compiled.])
AC_DEFINE_UNQUOTED(ODDJOB_DBUS_MINOR_VERSION,$DBUS_MINOR_VERSION,[Define to the minor version of D-BUS with which oddjob is being compiled.])
AC_DEFINE_UNQUOTED(ODDJOB_DBUS_MICRO_VERSION,$DBUS_MICRO_VERSION,[Define to the micro version of D-BUS with which oddjob is being compiled.])
AC_DEFINE_UNQUOTED(DBUS_API_SUBJECT_TO_CHANGE,"Then finish it!",[Define to allow use of DBus development versions.])

pam=yes
AC_CHECK_HEADERS(security/pam_modules.h)
savedLIBS="$LIBS"
LIBS=
AC_CHECK_FUNCS([pam_get_user pam_get_item],,[AC_CHECK_LIB(pam,pam_get_user,,pam=no)])
PAM_LIBS="$LIBS"
LIBS="$savedLIBS"
AC_SUBST(PAM_LIBS)
AM_CONDITIONAL(BUILD_PAM,test x$pam = xyes)

dnl Oh, for the clear management of OID arcs....
NAMESPACE=com.redhat
AC_SUBST(NAMESPACE)
NAMESPACEPATH=`echo "$NAMESPACE" | sed -e 's,^,/,' -e 's,\.,/,g'`
AC_SUBST(NAMESPACEPATH)
AC_DEFINE_UNQUOTED(ODDJOB_NAMESPACE,"$NAMESPACE",[Define to the namespace in which the oddjob service resides.])
AC_DEFINE_UNQUOTED(ODDJOB_NAMESPACE_PATH,"$NAMESPACEPATH",[Define to the prefix of the object paths used by oddjob.])

DEFAULT_FAST_RECONNECT_ATTEMPTS=10
AC_DEFINE_UNQUOTED(DEFAULT_FAST_RECONNECT_ATTEMPTS,$DEFAULT_FAST_RECONNECT_ATTEMPTS,[Define to the number of times oddjobd will attempt a "fast reconnect", before switching to waiting for the full reconnect timeout between attempts.])
AC_SUBST(DEFAULT_FAST_RECONNECT_ATTEMPTS)
DEFAULT_FAST_RECONNECT_TIMEOUT=5
AC_DEFINE_UNQUOTED(DEFAULT_FAST_RECONNECT_TIMEOUT,$DEFAULT_FAST_RECONNECT_TIMEOUT,[Define to the default amount of time which oddjobd will pause between attempts to reconnect to the system message bus after being disconnected for any reason.])
AC_SUBST(DEFAULT_FAST_RECONNECT_TIMEOUT)
DEFAULT_RECONNECT_TIMEOUT=30
AC_DEFINE_UNQUOTED(DEFAULT_RECONNECT_TIMEOUT,$DEFAULT_RECONNECT_TIMEOUT,[Define to the default amount of time which oddjobd will pause between attempts to reconnect to the system message bus after being disconnected for any reason.])
AC_SUBST(DEFAULT_RECONNECT_TIMEOUT)

AC_ARG_ENABLE(sample,
AS_HELP_STRING(--enable-sample,[Build and install a sample service.]),
sample=$withval,
sample=no)
AM_CONDITIONAL(INSTALL_SAMPLE,test x$sample = xyes)

AC_ARG_ENABLE(experimental,
AS_HELP_STRING(--enable-experimental,[Build experimental helpers.]),
experimental=$withval,
experimental=no)
AM_CONDITIONAL(ENABLE_EXPERIMENTAL,test x$experimental = xyes)

selinux_labels=default
AC_ARG_WITH(selinux-labels,
AS_HELP_STRING(--with-selinux-labels,[Apply SELinux labels to files created by helpers.]),
selinux_labels=$withval,
selinux_labels=default)

selinux_acls=default
AC_ARG_WITH(selinux-acls,
AS_HELP_STRING(--with-selinux-acls,[Recognize SELinux process attributes in oddjobd ACLs.]),
selinux_acls=$withval,
selinux_acls=default)

LIBSsave="$LIBS"
LIBS="$LIBS $DBUS_LIBS"
AC_CHECK_FUNCS(dbus_bus_release_name)
if test x$ac_cv_func_dbus_bus_release_name = xno ; then
	AC_MSG_WARN([D-Bus doesn't appear to provide dbus_bus_release_name(), oddjobd will be unable to unregister unused services when reloading configuration.])
fi
LIBS="$LIBSsave"

if test x$selinux_acls != xno ; then
	# Assume that if the "don't know what the client's context is" error
	# is defined, that the server supports being asked the question.
	CFLAGsave="$CFLAGS"
	CFLAGS="$CFLAGS $DBUS_CFLAGS"
	CPPFLAGsave="$CPPFLAGS"
	CPPFLAGS="$CPPFLAGS $DBUS_CFLAGS"
	AC_CHECK_DECL(DBUS_ERROR_SELINUX_SECURITY_CONTEXT_UNKNOWN,,,[
		      #include <dbus/dbus.h>
		      ])
	CFLAGS="$CFLAGsave"
	CPPFLAGS="$CPPFLAGsave"
	if test x$ac_cv_have_decl_DBUS_ERROR_SELINUX_SECURITY_CONTEXT_UNKNOWN != xyes ; then
		if test x$selinux_acls = xdefault ; then
			AC_MSG_WARN([D-Bus doesn't appear to provide GetConnectionSELinuxSecurityContext(), disabling SELinux ACL support.])
			selinux_acls=no
		else
			AC_MSG_ERROR([D-Bus doesn't appear to provide GetConnectionSELinuxSecurityContext(), stopping.])
		fi
	fi
fi

define_selinux_labels=false
SELINUX_CFLAGS=
SELINUX_LIBS=
if test x$selinux_labels != xno ; then
	CFLAGsave="$CFLAGS"
	LIBsave="$LIBS"
	CFLAGS=
	LIBS=
	if test -d $withval ; then
		CFLAGS="-I$withval/include"
		LIBS="-L$withval/`basename $libdir`"
	fi
	AC_CHECK_HEADERS(selinux/selinux.h)
	if test x$ac_cv_header_selinux_selinux_h != xyes ; then
		if test x$selinux != default ; then
			AC_MSG_ERROR([Could not locate SELinux headers.])
		else
			AC_MSG_WARN([Could not locate SELinux headers.])
		fi
	fi
	AC_CHECK_FUNC(setfscreatecon,,AC_CHECK_LIB(selinux,setfscreatecon))
	if test x$ac_cv_func_setfscreatecon != xyes ; then
		if test x$ac_cv_lib_selinux_setfscreatecon != xyes ; then
			if test x$selinux_labels != default ; then
				AC_MSG_ERROR([Could not locate SELinux library.])
			else
				AC_MSG_WARN([Could not locate SELinux library.])
			fi
		fi
	fi
	AC_CHECK_FUNCS(matchpathcon_init)
	if test x$ac_cv_header_selinux_selinux_h = xyes ; then
		if test x$ac_cv_func_setfscreatecon = xyes ; then
			define_selinux_labels=true
		fi
		if test x$ac_cv_lib_selinux_setfscreatecon = xyes ; then
			define_selinux_labels=true
		fi
	fi
	if $define_selinux_labels ; then
		AC_DEFINE(SELINUX_LABELS,1,[Define to build SELinux label-aware helpers.])
	fi
	SELINUX_CFLAGS="$CFLAGS"
	SELINUX_LIBS="$LIBS"
	CFLAGS="$CFLAGsave"
	LIBS="$LIBsave"
fi
#
#  Even if we have libselinux, D-BUS itself might not be able to give us the
#  info we need for enforcing SELinux ACLS, so jump through a flaming hoop.
#
SELINUX_ACLS_XML_START="<!-- "
SELINUX_ACLS_XML_END=" -->"
SELINUX_ACLS_MAN_SPECIFIC=".\\ "
if $define_selinux_labels ; then
	if test x$selinux_acls != xno ; then
		AC_DEFINE(SELINUX_ACLS,1,[Define if you want SELinux ACL support in oddjobd.])
		SELINUX_ACLS_XML_START=
		SELINUX_ACLS_XML_END=
		SELINUX_ACLS_MAN_SPECIFIC=
	fi
fi
AC_SUBST(SELINUX_CFLAGS)
AC_SUBST(SELINUX_LIBS)
AC_SUBST(SELINUX_ACLS_XML_START)
AC_SUBST(SELINUX_ACLS_XML_END)
AC_SUBST(SELINUX_ACLS_MAN_SPECIFIC)

python=default
AC_ARG_WITH(python,
AS_HELP_STRING(--with-python,[Build Python bindings for liboddjob.]),
python=$withval,
python=default)
if test x$python = xyes ; then
	AM_PATH_PYTHON(,,[
		if test x$python = xyes ; then
			AC_MSG_ERROR([no suitable Python interpreter found])
		fi
	])
fi
AM_CONDITIONAL(LIBODDJOB,false)
AM_CONDITIONAL(PYTHON,test x$python = xyes)

mysysconfdir=`eval echo "$sysconfdir" | sed s,^NONE,"$prefix",`
mysysconfdir=`eval echo "$mysysconfdir" | sed s,^NONE,"$ac_default_prefix",`
mydatadir=`eval echo "$datadir" | sed s,^NONE,"$prefix",`
mydatadir=`eval echo "$mydatadir" | sed s,^NONE,"$ac_default_prefix",`
mypkglibdir=`eval echo "$libdir/$PACKAGE" | sed s,^NONE,"$exec_prefix",`
mypkglibdir=`eval echo "$mypkglibdir" | sed s,^NONE,"$prefix",`
mypkglibdir=`eval echo "$mypkglibdir" | sed s,^NONE,"$ac_default_prefix",`
mypkglibexecdir=`eval echo "$libexecdir/$PACKAGE" | sed s,^NONE,"$exec_prefix",`
mypkglibexecdir=`eval echo "$mypkglibexecdir" | sed s,^NONE,"$prefix",`
mypkglibexecdir=`eval echo "$mypkglibexecdir" | sed s,^NONE,"$ac_default_prefix",`
mylocalstatedir=`eval echo "$localstatedir" | sed s,^NONE,"$prefix",`
mylocalstatedir=`eval echo "$mylocalstatedir" | sed s,^NONE,"$ac_default_prefix",`
AC_DEFINE_UNQUOTED(SYSCONFDIR,"$mysysconfdir",[Define to the directory in which oddjobd can find its configuration file.])
AC_DEFINE_UNQUOTED(PKGLIBDIR,"$mypkglibexecdir",[Define to a directory in which oddjobd can find some of its helpers.])
AC_DEFINE_UNQUOTED(PKGLIBEXECDIR,"$mypkglibexecdir",[Define to a directory in which oddjobd can find some of its helpers.])
AC_DEFINE_UNQUOTED(DATADIR,"$mydatadir",[Define to the directory in which shared data is stored.])
AC_DEFINE_UNQUOTED(LOCALSTATEDIR,"$mylocalstatedir",[Define to the directory in which local state information is stored.])
AC_DEFINE_UNQUOTED(LOCKDIR,"$mylocalstatedir/lock",[Define to the directory in which local lock information is kept.])
AC_SUBST(mypkglibdir)
AC_SUBST(mypkglibexecdir)
AC_SUBST(mysysconfdir)
AC_SUBST(mydatadir)

AC_PATH_PROGS(PATH_MOUNT,mount,/bin/mount)
AC_PATH_PROGS(PATH_UMOUNT,umount,/bin/umount)
AC_DEFINE_UNQUOTED(PATH_MOUNT,"$PATH_MOUNT", [Define to the path to the "mount" command.])
AC_DEFINE_UNQUOTED(PATH_UMOUNT,"$PATH_UMOUNT", [Define to the path to the "umount" command.])

if false ; then
libSAVE="$LIBS"
AC_CHECK_HEADERS(ldap.h)
if test x$ac_cv_header_ldap_h != xyes ; then
	AC_MSG_ERROR([Could not locate LDAP headers.])
fi
AC_CHECK_FUNC(ldap_init,,AC_CHECK_LIB(ldap,ldap_init))
if test x$ac_cv_func_ldap_init != xyes ; then
	if test x$ac_cv_lib_ldap_ldap_init != xyes ; then
		AC_MSG_ERROR([Could not locate LDAP library.])
	fi
fi
LDAP_LIBS="$LIBS"
AC_SUBST(LDAP_LIBS)
LIBS="$libSAVE"

libSAVE="$LIBS"
AC_CHECK_HEADERS(sasl/sasl.h)
if test x$ac_cv_header_sasl_sasl_h != xyes ; then
	AC_MSG_ERROR([Could not locate Cyrus SASL 2.x headers.])
fi
AC_CHECK_FUNC(sasl_client_init,,AC_CHECK_LIB(sasl2,sasl_client_init))
if test x$ac_cv_func_sasl_client_init != xyes ; then
	if test x$ac_cv_lib_sasl2_sasl_client_init != xyes ; then
		AC_MSG_ERROR([Could not locate Cyrus SASL 2.x library.])
	fi
fi
SASL_LIBS="$LIBS"
AC_SUBST(SASL_LIBS)
LIBS="$libSAVE"

libSAVE="$LIBS"
AC_PATH_PROGS(KRB5_CONFIG,krb5-config,not-found)
if test x$KRB5_CONFIG = xnot-found ; then
	AC_MSG_ERROR([Could not locate Kerberos libraries.])
fi
AC_MSG_CHECKING([for Kerberos 5 headers])
KRB5_CFLAGS=`$KRB5_CONFIG --cflags`
AC_MSG_RESULT($KRB5_CFLAGS)
AC_SUBST(KRB5_CFLAGS)
AC_MSG_CHECKING([for Kerberos 5 libraries])
KRB5_LIBS=`$KRB5_CONFIG --libs`
AC_MSG_RESULT($KRB5_LIBS)
AC_SUBST(KRB5_LIBS)
LIBS="$libSAVE"

cppflagsSAVE="$CPPFLAGS"
CPPFLAGS="$KRB5_CFLAGS"
AC_CHECK_HEADERS(et/com_err.h com_err.h)
CPPFLAGS="$cppflagsSAVE"

libSAVE="$LIBS"
AC_MSG_CHECKING([for GSSAPI headers])
GSSAPI_CFLAGS=`$KRB5_CONFIG --cflags gssapi`
AC_MSG_RESULT($GSSAPI_CFLAGS)
AC_SUBST(GSSAPI_CFLAGS)
AC_MSG_CHECKING([for GSSAPI libraries])
GSSAPI_LIBS=`$KRB5_CONFIG --libs gssapi`
AC_MSG_RESULT($GSSAPI_LIBS)
AC_SUBST(GSSAPI_LIBS)
LIBS="$libSAVE"
fi

AC_SYS_LARGEFILE
AC_CONFIG_HEADER(config.h)

AC_SUBST(DBUS_PACKAGE)
AC_DEFINE_UNQUOTED(DBUS_PACKAGE,"$DBUS_PACKAGE",[Define to the package name for D-BUS.])

AC_ARG_ENABLE(xml-docs,
AS_HELP_STRING(--enable-xml-docs,[Reformat XML documentation.]),
xml_docs=$withval,
xml_docs=no)
AM_CONDITIONAL(REFORMAT_XML_DOCS,test x$xml_docs = xyes)
AC_PATH_PROGS(PATH_XMLTO,xmlto,:)
AC_SUBST(PATH_XMLTO)

AC_ARG_ENABLE(compat-dtd,
AS_HELP_STRING(--enable-compat-dtd,[Use DocBook 4.3 instead of DocBook 4.4.]),
compat_dtd=$withval,
compat_dtd=no)
AC_MSG_CHECKING([which version of the DocBook DTD to use])
if test x$compat_dtd = xyes ; then
	DOCBOOK_PACKAGE_START=
	DOCBOOK_PACKAGE_END=
	DOCBOOK_VERSION=4.3
else
	DOCBOOK_PACKAGE_START="<package>"
	DOCBOOK_PACKAGE_END="</package>"
	DOCBOOK_VERSION=4.4
fi
AC_MSG_RESULT([$DOCBOOK_VERSION])
AC_SUBST(DOCBOOK_PACKAGE_START)
AC_SUBST(DOCBOOK_PACKAGE_END)
AC_SUBST(DOCBOOK_VERSION)

currentuser=`id -un`
AC_SUBST(currentuser)
currentgroup=`id -gn`
AC_SUBST(currentgroup)
currentuid=`id -u`
AC_SUBST(currentuid)
currentgid=`id -g`
AC_SUBST(currentgid)
AC_PATH_PROGS(PATH_PWD,pwd,pwd)
AC_PATH_PROGS(PATH_PWD,pwd,pwd)

AC_CONFIG_COMMANDS(src/mkhomedirfor+x,[chmod +x src/mkhomedirfor])
AC_CONFIG_COMMANDS(src/mkmyhomedir+x,[chmod +x src/mkmyhomedir])
AC_CONFIG_COMMANDS(src/reload+x,[chmod +x src/reload])
AC_CONFIG_COMMANDS(scripts/oddjobd+x,[chmod +x scripts/oddjobd])

AC_OUTPUT([
Makefile
autoversion
src/Makefile
scripts/Makefile
scripts/oddjobd
sample/Makefile
src/oddjob.pc
src/oddjob.conf
src/oddjob.conf.5
src/oddjobd.conf
src/oddjobd.conf.5
src/oddjobd-local.conf
src/oddjob_request.1
src/oddjobd.8
src/pam_oddjob_mkhomedir.8
src/oddjob-mkhomedir.conf
src/oddjobd-mkhomedir.conf
src/make-i11nconf.sh
src/printenv.sh
src/mkhomedirfor
src/mkmyhomedir
src/reload
python/Makefile
oddjobconfig.dtd
sample/oddjobd-sample.conf
sample/oddjob-sample.conf
sample/oddjob-sample.sh
doc/Makefile
doc/oddjob.xml
tests/Makefile
tests/test-oddjobd.conf
tests/sanity.sh
tests/006/expected_stdout
tests/007/expected_stdout
tests/008/expected_stdout
tests/cmdparse/Makefile
])
