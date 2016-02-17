#!/usr/sbin/dtrace -s

#pragma D option quiet

BEGIN {
	printf("[\n");
	comma=" ";
}

END {
  printf("]\n");
}

pid$1:::entry
{
	printf("%s {\"event\": \"%s:%s:%s:%s\", \"time\": %d, \"pid\": %d, \"tid\": %d, \"uid\": %d, \"exec\": \"%s\"}\n",
	    comma, probeprov, probemod, probefunc, probename, walltimestamp, pid, tid, uid, execname);
	comma=",";
}
