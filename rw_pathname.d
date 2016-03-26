#!/usr/sbin/dtrace -s

#pragma D option quiet

syscall::read:entry,syscall::write:entry
/pid != $pid  && execname != "sshd" && execname != "tmux"/
{
	printf("At %Y %s file %s by %s\n", walltimestamp, fds[arg0].fi_pathname, probefunc, execname)
}
