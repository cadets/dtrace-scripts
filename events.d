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

/* Temporarily disabled since FreeBSD does not support fi_pathname

syscall::read*:entry,syscall::write*:entry
/pid != $pid/
{
	printf("At %Y %s file %s by %s\n",
	    walltimestamp, fds[arg0].fi_pathname, probefunc, execname);
}

*/

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


ip:::send
/pid != $pid/
{
	printf(" %3d %10d %15s -> %15s %8s %6d\n", cpu, timestamp,
	    args[2]->ip_saddr, args[2]->ip_daddr, args[3]->if_name,
	    args[2]->ip_plength);
}

ip:::receive
/pid != $pid/
{
	printf(" %3d %10d %15s <- %15s %8s %6d\n", cpu, timestamp,
	    args[2]->ip_daddr, args[2]->ip_saddr, args[3]->if_name,
	    args[2]->ip_plength);
}

tcp:::send
/pid != $pid/

{
	this->length = args[2]->ip_plength - args[4]->tcp_offset;
	printf("%-3d %15s:%-5d  ->  %15s:%-5d %6d (", cpu,
	    args[2]->ip_saddr, args[4]->tcp_sport,
	    args[2]->ip_daddr, args[4]->tcp_dport, this->length);
}

tcp:::receive
/pid != $pid/

{
	this->length = args[2]->ip_plength - args[4]->tcp_offset;
	printf("%-3d %15s:%-5d  <-  %15s:%-5d %6d (", cpu,
	    args[2]->ip_daddr, args[4]->tcp_dport,
	    args[2]->ip_saddr, args[4]->tcp_sport, this->length);
}

tcp:::send,
tcp:::receive
/pid != $pid/
{
	printf("%s", args[4]->tcp_flags & TH_FIN ? "FIN|" : "");
	printf("%s", args[4]->tcp_flags & TH_SYN ? "SYN|" : "");
	printf("%s", args[4]->tcp_flags & TH_RST ? "RST|" : "");
	printf("%s", args[4]->tcp_flags & TH_PUSH ? "PUSH|" : "");
	printf("%s", args[4]->tcp_flags & TH_ACK ? "ACK|" : "");
	printf("%s", args[4]->tcp_flags & TH_URG ? "URG|" : "");
	printf("%s", args[4]->tcp_flags & TH_ECE ? "ECE|" : "");
	printf("%s", args[4]->tcp_flags & TH_CWR ? "CWR|" : "");
	printf("%s", args[4]->tcp_flags == 0 ? "null " : "");
	printf("\b)\n");
}
