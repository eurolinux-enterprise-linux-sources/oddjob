#!/bin/sh
#
#  Start the session bus and arrange for it to be stopped when we exit.
#
DBUS_SESSION_BUS_PID=
eval `dbus-launch --sh-syntax`
if test -z "$DBUS_SESSION_BUS_PID" ; then
	echo Error starting session bus.
	exit 1
fi
stopbus() {
	kill "$DBUS_SESSION_BUS_PID"
}
trap stopbus EXIT
#
#  Now fix the PATH.
#
PATH=../src:${PATH}
#
#  Process arguments.
#
monitor=
post=:
LD_PRELOAD=
for arg in "$@" ; do
	case "$arg" in
	--efence)
		LD_PRELOAD=libefence.so
		export LD_PRELOAD
		;;
	--memcheck)
		monitor="valgrind --tool=memcheck --leak-check=yes -v --show-reachable=yes --num-callers=30 --log-fd=3 --error-limit=no --time-stamp=yes"
		;;
	--strace)
		post='strace -s2048 -f -o test-oddjobd.log -p '
		;;
	--sleep=*)
		sleep `echo x"$arg" | cut -f2- -d=`
		;;
	esac
done
$monitor oddjobd -S -n -c test-oddjobd.conf -p test-oddjobd.pid 3> test-oddjobd.log &
sleep 5
ODDJOBD_PID=`cat test-oddjobd.pid`
if test "$post" != : ; then
	$post $ODDJOBD_PID &
fi
chmod +x sanity.sh printenv.sh
for subdir in * ; do
	if test -d "$subdir" -a -e "$subdir"/args ; then
		if test -s "$subdir"/args ; then
			args=`cat "$subdir"/args 2> /dev/null`
		else
			args=
		fi
		sleep 1
		oddjob_request -S $args > stdout 2> stderr
		status=$?
		expected_status=`cat "$subdir"/exit_status`
		exit_error=false
		if test $expected_status -ne $status ; then
			echo "$subdir": exit status mismatch: got ${status} instead of ${expected_status}.
			exit_error=true
		fi
		stdout_error=true
		for stdout in "$subdir"/expected_stdout* ; do
			case "$stdout" in
			*.in) continue;;
			esac
			if cmp -s stdout $stdout 2> /dev/null ; then
				stdout_error=false
			fi
		done
		if $stdout_error ; then
			for stdout in "$subdir"/expected_stdout* ; do
				case "$stdout" in
				*.in) continue;;
				esac
				if ! cmp -s stdout $stdout 2> /dev/null ; then
					diff -u $stdout stdout
				fi
			done
		fi
		stderr_error=true
		for stderr in "$subdir"/expected_stderr* ; do
			case "$stderr" in
			*.in) continue;;
			esac
			if cmp -s stderr $stderr 2> /dev/null ; then
				stderr_error=false
			fi
		done
		if $stderr_error ; then
			for stderr in "$subdir"/expected_stderr* ; do
				case "$stderr" in
				*.in) continue;;
				esac
				if ! cmp -s stderr $stderr 2> /dev/null ; then
					diff -u $stderr stderr
				fi
			done
		fi
		if $exit_error || $stdout_error || $stderr_error ; then
			echo FAIL
			break
		fi
		if test -s "$subdir"/description ; then
			echo `cat "$subdir"/description`: PASS
		else
			echo "$subdir": PASS
		fi
	fi
done
oddjob_request -S quit
exit 0
