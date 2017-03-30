/*
 * File: boot.d
 *
 * boot time script for anonymous tracing
 *
 * Usage
 *
 * # dtrace -ACs boot.d
 * # shutdown -r now
 * # dtrace -ae > /tmp/boot.d.out
 *
 * During boot we do not have the audit provider.  This is a simple
 * script to grab a few of the events we know we'll want, including
 * name lookup and program execution, under anymous tracing.
*/

#pragma D option quiet
#pragma D option switchrate=1000hz
#pragma D option dynvarsize=16m
#pragma D option bufsize=64m
#pragma D option strsize=4k

inline int af_inet = 2 /*AF_INET*/;
inline int af_inet6 = 28 /*AF_INET6*/;

/*
 * BEGIN and END probes
 */
BEGIN {
    printf("[\n");
    comma=" ";
}

END {
  printf("]\n");
}

/* XXX: proc_filter */
/* Default filter on processes */
#define proc_filter_def (pid != $pid)
/* Filter on processes for read/write/mmap */
#define proc_filter_rw (pid != $pid) && (execname != "sshd") && \
	(execname != "tmux") && (execname != "moused")

proc:kernel::exec
/(pid != $pid)
#if FILTER_PYTHON
&& (execname != "python3.4")
#endif
#if FILTER_UID
&& (uid != 1002)
#endif
/
{
    printf("%s {\"event\": \"%s:%s:%s:\"", comma, probeprov, probemod, probefunc);
    printf(", \"time\": %d", walltimestamp);
    printf(", \"pid\": %d", pid);
    printf(", \"ppid\": %d",ppid);
    printf(", \"tid\": %d", tid);
    printf(", \"uid\": %d", uid);
    printf(", \"exec\": \"%s\"", stringof(args[0]));
    printf(", \"procuuid\": \"%U\"", curthread->td_proc->p_uuid);
    printf(", \"thruuid\": \"%U\"", curthread->td_uuid);
    printf("}\n");
    comma=",";
}

vfs:namei:lookup:entry
/(pid != $pid)
#if FILTER_PYTHON
&& (execname != "python3.4")
#endif
#if FILTER_UID
&& (uid != 1002)
#endif
/
{
    printf("%s {\"event\": \"%s:%s:%s:\"", comma, probeprov, probemod, probefunc);
    printf(", \"time\": %d", walltimestamp);
    printf(", \"pid\": %d", pid);
    printf(", \"ppid\": %d",ppid);
    printf(", \"tid\": %d", tid);
    printf(", \"uid\": %d", uid);
    printf(", \"lookup\": \"%s\"", stringof(args[1]));
    printf(", \"procuuid\": \"%U\"", curthread->td_proc->p_uuid);
    printf(", \"thruuid\": \"%U\"", curthread->td_uuid);
    printf("}\n");
    comma=",";
}

tcp:::accept-established
/(pid != $pid)/
{
	printf("Accept connection from %s:%d to %s:%d on UUID %U\n",
		       args[2]->ip_saddr,
		       args[4]->tcp_sport,
		       args[2]->ip_daddr,
		       args[4]->tcp_dport,
		       ((struct tcpcb *)args[3]->tcps_addr)->t_inpcb->inp_socket->so_uuid);
}

tcp:::connect-established
/(pid != $pid)/
{
	printf("Established connection to %s:%d from %s:%d on UUID %U\n",
		       args[2]->ip_saddr,
		       args[4]->tcp_sport,
		       args[2]->ip_daddr,
		       args[4]->tcp_dport,
		       ((struct tcpcb *)args[3]->tcps_addr)->t_inpcb->inp_socket->so_uuid);
}

