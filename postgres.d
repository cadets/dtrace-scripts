#!/usr/sbin/dtrace -s

#pragma D option quiet
#pragma D option switchrate=10hz
#pragma D option dynvarsize=16m
#pragma D option bufsize=8m

/* If AF_INET and AF_INET6 are "Unknown" to DTrace, replace with numbers: */
inline int af_inet = 2 /*AF_INET*/;
inline int af_inet6 = 28 /*AF_INET6*/;

BEGIN {
	printf("[\n");
	comma=" ";
}

END {
  printf("]\n");
}

postgresql$target:::transaction*
{
    /* probeprov:probemod:probefunc:probname */
	printf("%s {\"event\": \"%s:%s:%s:%s\", \"time\": %d, \"pid\": %d, \"tid\": %d, \"uid\": %d, \"exec\": \"%s\", \"id\": \"%s\"}\n",
	    comma, probeprov, probemod, probefunc, probename, walltimestamp, pid, tid, uid, execname, copyinstr(arg0));
	comma=",";
}

postgresql$target:::query-start,
postgresql$target:::query-done
{
	printf("%s {\"event\": \"%s:%s:%s:%s\", \"time\": %d, \"pid\": %d, \"tid\": %d, \"uid\": %d, \"exec\": \"%s\", \"query\": \"%s\"}\n",
	    comma, probeprov, probemod, probefunc, probename, walltimestamp, pid, tid, uid, execname, copyinstr(arg0));
	comma=",";
}
