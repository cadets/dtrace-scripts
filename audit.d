#!/usr/sbin/dtrace -Cs

#pragma D option quiet
#pragma D option switchrate=10hz
#pragma D option dynvarsize=16m
#pragma D option bufsize=16m
#pragma D option strsize=1024

inline int af_inet = 2 /*AF_INET*/;
inline int af_inet6 = 28 /*AF_INET6*/;

/* FROM security/audit/audit_private.h
 *
 * Arguments in the audit record are initially not defined; flags are set to
 * indicate if they are present so they can be included in the audit log
 * stream only if defined.
 */
#define ARG_EUID           0x0000000000000001ULL
#define ARG_RUID           0x0000000000000002ULL
#define ARG_SUID           0x0000000000000004ULL
#define ARG_EGID           0x0000000000000008ULL
#define ARG_RGID           0x0000000000000010ULL
#define ARG_SGID           0x0000000000000020ULL
#define ARG_PID            0x0000000000000040ULL
#define ARG_UID            0x0000000000000080ULL
#define ARG_AUID           0x0000000000000100ULL
#define ARG_GID            0x0000000000000200ULL
#define ARG_FD             0x0000000000000400ULL
#define ARG_POSIX_IPC_PERM 0x0000000000000800ULL
#define ARG_FFLAGS         0x0000000000001000ULL
#define ARG_MODE           0x0000000000002000ULL
#define ARG_DEV            0x0000000000004000ULL
#define ARG_ADDR           0x0000000000008000ULL
#define ARG_LEN            0x0000000000010000ULL
#define ARG_MASK           0x0000000000020000ULL
#define ARG_SIGNUM         0x0000000000040000ULL
#define ARG_LOGIN          0x0000000000080000ULL
#define ARG_SADDRINET      0x0000000000100000ULL
#define ARG_SADDRINET6     0x0000000000200000ULL
#define ARG_SADDRUNIX      0x0000000000400000ULL
#define ARG_TERMID_ADDR    0x0000000000400000ULL
#define ARG_UNUSED2        0x0000000001000000ULL
#define ARG_UPATH1         0x0000000002000000ULL
#define ARG_UPATH2         0x0000000004000000ULL
#define ARG_TEXT           0x0000000008000000ULL
#define ARG_VNODE1         0x0000000010000000ULL
#define ARG_VNODE2         0x0000000020000000ULL
#define ARG_SVIPC_CMD      0x0000000040000000ULL
#define ARG_SVIPC_PERM     0x0000000080000000ULL
#define ARG_SVIPC_ID       0x0000000100000000ULL
#define ARG_SVIPC_ADDR     0x0000000200000000ULL
#define ARG_GROUPSET       0x0000000400000000ULL
#define ARG_CMD            0x0000000800000000ULL
#define ARG_SOCKINFO       0x0000001000000000ULL
#define ARG_ASID           0x0000002000000000ULL
#define ARG_TERMID         0x0000004000000000ULL
#define ARG_AUDITON        0x0000008000000000ULL
#define ARG_VALUE          0x0000010000000000ULL
#define ARG_AMASK          0x0000020000000000ULL
#define ARG_CTLNAME        0x0000040000000000ULL
#define ARG_PROCESS        0x0000080000000000ULL
#define ARG_MACHPORT1      0x0000100000000000ULL
#define ARG_MACHPORT2      0x0000200000000000ULL
#define ARG_EXIT           0x0000400000000000ULL
#define ARG_IOVECSTR       0x0000800000000000ULL
#define ARG_ARGV           0x0001000000000000ULL
#define ARG_ENVV           0x0002000000000000ULL
#define ARG_ATFD1          0x0004000000000000ULL
#define ARG_ATFD2          0x0008000000000000ULL
#define ARG_RIGHTS         0x0010000000000000ULL
#define ARG_FCNTL_RIGHTS   0x0020000000000000ULL
#define ARG_PROCUUID       0x0040000000000000ULL
#define ARG_OBJUUID1       0x0080000000000000ULL
#define ARG_OBJUUID2       0x0100000000000000ULL
#define ARG_NONE           0x0000000000000000ULL
#define ARG_ALL            0xFFFFFFFFFFFFFFFFULL
#define IS_VALID(arg)  (args[1]->ar_valid_arg & (arg))

BEGIN {
    printf("[\n");
    comma=" ";
}

END {
  printf("]\n");
}

/*
audit::aue_*:commit
/pid != $pid/
{
    this->record = (struct audit_record*) arg1;
    printf("%s {\"event\": \"%s:%s:%s:\", \"valid_mask\": %x }\n",
        comma, probeprov, probemod, probefunc, this->record->ar_valid_arg);
}
*/

audit::aue_fexecve:commit,
audit::aue_exec:commit,
audit::aue_execve:commit
/pid != $pid/
{
    this->record = (struct audit_record*) arg1;
    printf("%s {\"event\": \"%s:%s:%s:\", \"time\": %d, \"pid\": %d, \"puuid\": \"%U\", \"ppid\": %d, \"tid\": %d, \"uid\": %d, \"exec\": \"%s\", \"new_exec\": \"%s\"}\n",
        comma, probeprov, probemod, probefunc, walltimestamp, pid, args[1]->ar_subj_uuid, ppid, tid, uid, this->record->ar_subj_comm, IS_VALID(ARG_UPATH1)?this->record->ar_arg_upath1:execname);
    comma=",";
}

audit::aue_open*:commit
/pid != $pid && args[1]->ar_retval >= 0/
{
    this->record = (struct audit_record*) arg1;
    printf("%s {\"event\": \"%s:%s:%s:\", \"time\": %d, \"pid\": %d, \"puuid\": \"%U\", \"ppid\": %d, \"tid\": %d, \"uid\": %d, \"exec\": \"%s\", \"path\": \"%s\", \"fd\": %d, \"args\": \"0x%x\" }\n",
            comma, probeprov, probemod, probefunc, walltimestamp, pid, args[1]->ar_subj_uuid, ppid, tid, uid, execname, IS_VALID(ARG_UPATH1)?stringof(this->record->ar_arg_upath1):"", this->record->ar_retval, IS_VALID(ARG_FFLAGS)?this->record->ar_arg_fflags:0);
    comma=",";
}

audit::aue_close:commit
/pid != $pid /
{
    /* TODO path */
    this->record = (struct audit_record*) arg1;
    printf("%s {\"event\": \"%s:%s:%s:\", \"time\": %d, \"pid\": %d, \"puuid\": \"%U\", \"ppid\": %d, \"tid\": %d, \"uid\": %d, \"exec\": \"%s\", \"path\": \"%s\", \"fd\": %d }\n",
        comma, probeprov, probemod, probefunc, walltimestamp, pid, args[1]->ar_subj_uuid, ppid, tid, uid, execname, IS_VALID(ARG_UPATH1)?stringof(this->record->ar_arg_upath1):"", IS_VALID(ARG_FD)?this->record->ar_arg_fd:-1);
    comma=",";
}

audit::aue_fork:commit,
audit::aue_vfork:commit,
audit::aue_rfork:commit
/pid != $pid && args[1]->ar_retval >= 0 && IS_VALID(ARG_PROCUUID)/
{
    this->record = (struct audit_record*) arg1;
    printf("%s {\"event\": \"%s:%s:%s:\", \"time\": %d, \"pid\": %d, \"puuid\": \"%U\", \"ppid\": %d, \"tid\": %d, \"uid\": %d, \"exec\": \"%s\", \"new_pid\": %d, \"new_puuid\": \"%U\" }\n",
        comma, probeprov, probemod, probefunc, walltimestamp, pid, args[1]->ar_subj_uuid, ppid, tid, uid, execname, IS_VALID(ARG_PID)?this->record->ar_arg_pid:-1, this->record->ar_arg_procuuid);
    comma=",";
}
audit::aue_fork:commit,
audit::aue_vfork:commit,
audit::aue_rfork:commit
/pid != $pid && args[1]->ar_retval >= 0 && !IS_VALID(ARG_PROCUUID)/
{
    this->record = (struct audit_record*) arg1;
    printf("%s {\"event\": \"%s:%s:%s:\", \"time\": %d, \"pid\": %d, \"puuid\": \"%U\", \"ppid\": %d, \"tid\": %d, \"uid\": %d, \"exec\": \"%s\", \"new_pid\": %d}\n",
        comma, probeprov, probemod, probefunc, walltimestamp, pid, args[1]->ar_subj_uuid, ppid, tid, uid, execname, IS_VALID(ARG_PID)?this->record->ar_arg_pid:-1);
    comma=",";
}

audit::aue_dup*:commit
/pid != $pid/
{
    this->record = (struct audit_record*) arg1;
    printf("%s {\"event\": \"%s:%s:%s:\", \"time\": %d, \"pid\": %d, \"puuid\": \"%U\", \"ppid\": %d, \"tid\": %d, \"uid\": %d, \"exec\": \"%s\", \"new_fd\": %d, \"fd\": %d }\n",
        comma, probeprov, probemod, probefunc, walltimestamp, this->record->ar_subj_pid, args[1]->ar_subj_uuid, ppid, tid, this->record->ar_subj_ruid, execname, this->record->ar_retval, IS_VALID(ARG_FD)?this->record->ar_arg_fd:-1);
    comma=",";
}

audit::aue_*read:commit,
audit::aue_*readv:commit,
audit::aue_*write:commit,
audit::aue_*writev:commit
/pid != $pid && execname != "sshd" && execname != "tmux" && execname != "moused" /
{
    /*TODO missing path */
    this->record = (struct audit_record*) arg1;
    printf("%s {\"event\": \"%s:%s:%s:\", \"time\": %d, \"pid\": %d, \"puuid\": \"%U\", \"ppid\": %d, \"tid\": %d, \"uid\": %d, \"exec\": \"%s\", \"fd\": %d, \"path\": \"%s\" }\n",
        comma, probeprov, probemod, probefunc, walltimestamp, pid, args[1]->ar_subj_uuid, ppid, tid, uid, execname, IS_VALID(ARG_FD)?this->record->ar_arg_fd:-1, IS_VALID(ARG_UPATH1)?this->record->ar_arg_upath1:"");
    comma=",";
}

audit::aue_exit:commit
/pid != $pid/
{
    printf("%s {\"event\": \"%s:%s:%s:\", \"time\": %d, \"pid\": %d, \"puuid\": \"%U\", \"ppid\": %d, \"tid\": %d, \"uid\": %d, \"exec\": \"%s\"}\n",
        comma, probeprov, probemod, probefunc, walltimestamp, pid, args[1]->ar_subj_uuid, ppid, tid, uid, execname);
    comma=",";
}

audit::aue_mmap:commit
/IS_VALID(ARG_FD) && args[1]->ar_arg_fd != -1 && pid != $pid && execname != "sshd" && execname != "tmux" && execname != "moused"/
{
    /*TODO missing path */
    this->record = (struct audit_record*) arg1;
    printf("%s {\"event\": \"%s:%s:%s:\", \"time\": %d, \"pid\": %d, \"puuid\": \"%U\", \"ppid\": %d, \"tid\": %d, \"uid\": %d, \"exec\": \"%s\", \"fd\": %d, \"path\": \"%s\" }\n",
        comma, probeprov, probemod, probefunc, walltimestamp, pid, args[1]->ar_subj_uuid, ppid, tid, uid, execname, this->record->ar_arg_fd, IS_VALID(ARG_UPATH1)?this->record->ar_arg_upath1:"");
    comma=",";
}

audit::aue_connect*:commit
/pid != $pid/
{
    this->record = (struct audit_record*) arg1;
    this->sockaddr = IS_VALID(ARG_SADDRINET)?
                        inet_ntop(af_inet,(void*)&((struct sockaddr_in*) &this->record->ar_arg_sockaddr)->sin_addr)
                     :IS_VALID(ARG_SADDRINET6)?
                        inet_ntoa6(&((struct sockaddr_in6*) &this->record->ar_arg_sockaddr)->sin6_addr)
                     :IS_VALID(ARG_SADDRUNIX)?
                        ((struct sockaddr_un*) &this->record->ar_arg_sockaddr)->sun_path
                     :"";
    this->sockport = IS_VALID(ARG_SADDRINET)?
                        ntohs(((struct sockaddr_in*) &this->record->ar_arg_sockaddr)->sin_port)
                     :IS_VALID(ARG_SADDRINET6)?
                        ntohs(((struct sockaddr_in6*) &this->record->ar_arg_sockaddr)->sin6_port)
                     : -1;
    printf("%s {\"event\": \"%s:%s:%s:\", \"time\": %d, \"pid\": %d, \"puuid\": \"%U\", \"ppid\": %d, \"tid\": %d, \"uid\": %d, \"exec\": \"%s\", \"family\": %d, \"address\": \"%s\", \"port\": %d, \"err\": %d}\n",
        comma, probeprov, probemod, probefunc, walltimestamp, pid, args[1]->ar_subj_uuid, ppid, tid, uid, execname,
        IS_VALID(ARG_SADDRINET)?af_inet:IS_VALID(ARG_SADDRINET6)?af_inet6:-1,
        this->sockaddr, this->sockport, errno);
    comma=",";
}

audit::aue_accept*:commit
/pid != $pid/
{
    this->record = (struct audit_record*) arg1;
    this->sockaddr = IS_VALID(ARG_SADDRINET)?
                        inet_ntop(af_inet,(void*)&((struct sockaddr_in*) &this->record->ar_arg_sockaddr)->sin_addr)
                     :IS_VALID(ARG_SADDRINET6)?
                        inet_ntoa6(&((struct sockaddr_in6*) &this->record->ar_arg_sockaddr)->sin6_addr)
                     :IS_VALID(ARG_SADDRUNIX)?
                        ((struct sockaddr_un*) &this->record->ar_arg_sockaddr)->sun_path
                     :"";
    this->sockport = IS_VALID(ARG_SADDRINET)?
                        ntohs(((struct sockaddr_in*) &this->record->ar_arg_sockaddr)->sin_port)
                     :IS_VALID(ARG_SADDRINET6)?
                        ntohs(((struct sockaddr_in6*) &this->record->ar_arg_sockaddr)->sin6_port)
                     : -1;
    printf("%s {\"event\": \"%s:%s:%s:\", \"time\": %d, \"pid\": %d, \"puuid\": \"%U\", \"ppid\": %d, \"tid\": %d, \"uid\": %d, \"exec\": \"%s\", \"family\": %d, \"address\": \"%s\", \"port\": %d, \"err\": %d}\n",
        comma, probeprov, probemod, probefunc, walltimestamp, pid, args[1]->ar_subj_uuid, ppid, tid, uid, execname,
        IS_VALID(ARG_SADDRINET)?af_inet:IS_VALID(ARG_SADDRINET6)?af_inet6:-1,
        this->sockaddr, this->sockport, errno);
    comma=",";
}
