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

pid$target:nginx::entry
{
	printf("%s {\"event\": \"%s:%s:%s:%s\", \"time\": %d, \"pid\": %d, \"tid\": %d, \"uid\": %d, \"exec\": \"%s\"}\n",
	    comma, probeprov, probemod, probefunc, probename, walltimestamp, pid, tid, uid, execname);
	comma=",";
}

pid$target:nginx::return
{
	printf("%s {\"event\": \"%s:%s:%s:%s\", \"time\": %d, \"pid\": %d, \"tid\": %d, \"uid\": %d, \"exec\": \"%s\"}\n",
	    comma, probeprov, probemod, probefunc, probename, walltimestamp, pid, tid, uid, execname);
	comma=",";
}

/* Ugly hack to get HTTP request. Clean up when we have CTF */
pid$target::*ngx_http_process_request:entry
{
	this->request_len = *(int *)copyin(arg0+816, sizeof(int));
	this->request_ptr = *(uintptr_t *)copyin(arg0+824, sizeof(uintptr_t));
        this->request = stringof(copyin(this->request_ptr, this->request_len));
	printf("%s {\"event\": \"%s:%s:%s:%s\", \"time\": %d, \"pid\": %d, \"tid\": %d, \"uid\": %d, \"exec\": \"%s\", \"request\": \"%s\"}\n",
	    comma, probeprov, probemod, probefunc, probename, walltimestamp, pid, tid, uid, execname, this->request);
	comma=",";
}

/*
pid$target:nginx:main:entry
{
	printf("%s {\"event\": \"%s:%s:%s:%s\", \"time\": %d, \"pid\": %d, \"tid\": %d, \"uid\": %d, \"exec\": \"%s\", \"args\": \"%s\"}\n",
	    comma, probeprov, probemod, probefunc, probename, walltimestamp, pid, tid, uid, execname, "WIP");
	comma=",";
}

pid$target:nginx:ngx_signal_process:entry
{
	printf("%s {\"event\": \"%s:%s:%s:%s\", \"time\": %d, \"pid\": %d, \"tid\": %d, \"uid\": %d, \"exec\": \"%s\", \"args\": \"%s\"}\n",
	    comma, probeprov, probemod, probefunc, probename, walltimestamp, pid, tid, uid, execname, copyinstr(arg1));
	comma=",";
}

pid$target::main:entry 
{ 
    printf("arg1: %s", copyinstr(arg1)); 
}
*/
