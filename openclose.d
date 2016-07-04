#!/usr/sbin/dtrace -s
/*
 * Test only the open() and close() system call's use of the
 * fi_pathname member of the fds[] array.
 *
 * Usage: openclose.d (either sudo or as root)
 */

#pragma D option quiet
#pragma D option switchrate=100hz
#pragma D option dynvarsize=16m
#pragma D option bufsize=16m
#pragma D option strsize=1024

syscall::open:return
/pid != $pid/
{
	printf("{\"event\": \"%s:%s:%s:\", \"time\": %d, \"pid\": %d, \"ppid\": %d, \"tid\": %d, \"uid\": %d, \"exec\": \"%s\", \"dir\": \"%s\",\"path\": \"%s\", \"fd\": %d }\n",
	       probeprov, probemod, probefunc, walltimestamp, pid, ppid, tid, uid, execname, fds[arg1].fi_dirname, fds[arg1].fi_pathname, arg1);
}


syscall::close:entry
/pid != $pid/
{
	printf("{\"event\": \"%s:%s:%s:\", \"time\": %d, \"pid\": %d, \"ppid\": %d, \"tid\": %d, \"uid\": %d, \"exec\": \"%s\", \"dir\": \"%s\",\"path\": \"%s\", \"fd\": %d }\n",
	       probeprov, probemod, probefunc, walltimestamp, pid, ppid, tid, uid, execname, fds[arg0].fi_dirname, fds[arg0].fi_pathname, arg0);
}
