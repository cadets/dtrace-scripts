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

/*
pid$target:nginx::entry
{
	printf("%s {\"event\": \"%s:%s\", \"time\": %d, \"pid\": %d, \"tid\": %d, \"uid\": %d, \"exec\": \"%s\"}\n",
	    comma, probefunc, probename, walltimestamp, pid, tid, uid, execname);
}

pid$target:nginx::return
{
	printf("%s {\"event\": \"%s:%s\", \"time\": %d, \"pid\": %d, \"tid\": %d, \"uid\": %d, \"exec\": \"%s\"}\n",
	    comma, probefunc, probename, walltimestamp, pid, tid, uid, execname);
}
*/



pid$target:nginx:main:entry
{
	printf("%s {\"event\": \"%s:%s\", \"time\": %d, \"pid\": %d, \"tid\": %d, \"uid\": %d, \"exec\": \"%s\", \"args\": \"%s\"}\n",
	    comma, probefunc, probename, walltimestamp, pid, tid, uid, execname, "WIP");
	comma=",";
}

pid$target:nginx:ngx_signal_process:entry
{
	printf("%s {\"event\": \"%s:%s\", \"time\": %d, \"pid\": %d, \"tid\": %d, \"uid\": %d, \"exec\": \"%s\", \"args\": \"%s\"}\n",
	    comma, probefunc, probename, walltimestamp, pid, tid, uid, execname, copyinstr(arg1));
	comma=",";
}

/*
pid$target::main:entry 
{ 
    printf("arg1: %s", copyinstr(arg1)); 
}
*/

