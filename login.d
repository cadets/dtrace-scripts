#!/usr/sbin/dtrace -s

#pragma D option quiet
#pragma D option switchrate=10hz
#pragma D option dynvarsize=16m
#pragma D option bufsize=16m
#pragma D option strsize=1024

BEGIN {
	printf("[\n");
	comma=" ";
}

END {
  printf("]\n");
}

/*
 * Print out username for successful log ins.
 */
syscall::*login:entry
/pid != $pid/
{
	printf("%s {\"event\": \"%s:%s:%s:%s\", \"time\": %d, \"pid\": %d, \"tid\": %d, \"uid\": %d, \"exec\": \"%s\", \"username\": \"%s\"}\n",
	    comma, probeprov, probemod, probefunc, probename, walltimestamp, pid, tid, uid, execname, copyinstr(arg0));
	comma=",";
}

/*
syscall::*login:return
/pid != $pid/
{
	printf("%s {\"event\": \"%s:%s:%s:%s\", \"time\": %d, \"pid\": %d, \"tid\": %d, \"uid\": %d, \"exec\": \"%s\", \"success\": \"%s\"}\n",
	    comma, probeprov, probemod, probefunc, probename, walltimestamp, pid, tid, uid, execname, arg0 ? "false" : "true");
	comma=",";
}
*/

