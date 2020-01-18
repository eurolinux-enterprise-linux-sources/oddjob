EXTRA_DIST = oddjobd.in oddjobd.service.in
if SYSVINIT
initdir = $(sysconfdir)/rc.d/init.d
init_SCRIPTS = oddjobd
endif
if SYSTEMD
unitdir = @SYSTEMDSYSTEMUNITDIR@
unit_DATA = oddjobd.service
endif
