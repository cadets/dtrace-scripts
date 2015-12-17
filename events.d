#!/usr/sbin/dtrace -s

#pragma D option quiet
#pragma D option switchrate=10hz
#pragma D option dynvarsize=16m
#pragma D option bufsize=8m

syscall::open*:entry
/pid != $pid/
{
	printf("At %Y %s file opened by PID %d UID %d using %s\n",
	    walltimestamp, copyinstr(arg0), pid, uid, execname);
}


syscall::read*:entry,syscall::write*:entry
/pid != $pid/
{
	printf("At %Y %s file %s by %s\n",
	    walltimestamp, fds[arg0].fi_pathname, probefunc, execname);
}

proc:::exec-success
/pid != $pid/
{
	trace(curpsinfo->pr_psargs);
}


syscall::exec*:return
/pid != $pid/
{
	printf("exec: %Y %s\n", walltimestamp, curpsinfo->pr_psargs);
}

syscall::fork*:entry
/pid != $pid/
{
	printf("fork: %s %d", execname, pid);
}
