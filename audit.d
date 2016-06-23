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

audit::aue_fexecve:commit
/pid != $pid/
{
    this->record = (struct audit_record*) arg1;
    printf("%s {\"event\": \"%s:%s:%s:\", \"time\": %d, \"pid\": %d, \"ppid\": %d, \"tid\": %d, \"uid\": %d, \"exec\": \"%s\"}\n",
        comma, probeprov, probemod, probefunc, walltimestamp, this->record->ar_subj_pid, ppid, tid, this->record->ar_subj_ruid, execname);
    comma=",";
}

audit::aue_exec:commit
/pid != $pid/
{
    this->record = (struct audit_record*) arg1;
    printf("%s {\"event\": \"%s:%s:%s:\", \"time\": %d, \"pid\": %d, \"ppid\": %d, \"tid\": %d, \"uid\": %d, \"exec\": \"%s\"}\n",
        comma, probeprov, probemod, probefunc, walltimestamp, this->record->ar_subj_pid, ppid, tid, this->record->ar_subj_ruid, execname);
    comma=",";
}

audit::aue_execve:commit
/pid != $pid/
{
    this->record = (struct audit_record*) arg1;
    printf("%s {\"event\": \"%s:%s:%s:\", \"time\": %d, \"pid\": %d, \"ppid\": %d, \"tid\": %d, \"uid\": %d, \"exec\": \"%s\"}\n",
        comma, probeprov, probemod, probefunc, walltimestamp, this->record->ar_subj_pid, ppid, tid, this->record->ar_subj_ruid, execname);
    comma=",";
}
