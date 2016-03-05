#!/usr/sbin/dtrace -s

#pragma D option quiet
#pragma D option switchrate=10hz
#pragma D option dynvarsize=16m
#pragma D option bufsize=8m

BEGIN {
	printf("[\n");
	comma=" ";
}

END {
  printf("]\n");
}

postgresql*:::query-start
{
	printf("%s {\"event\": \"%s:%s:%s:%s\", \"time\": %d, \"pid\": %d, \"tid\": %d, \"uid\": %d, \"exec\": \"%s\", \"query\": \"%s\"}\n",
	    comma, probeprov, probemod, probefunc, probename, walltimestamp, pid, tid, uid, execname, copyinstr(arg0));
	comma=",";
}
