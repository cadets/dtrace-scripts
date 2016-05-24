#!/usr/sbin/dtrace -s

#pragma D option quiet
#pragma D option switchrate=10hz
#pragma D option dynvarsize=16m
#pragma D option bufsize=16m
#pragma D option strsize=1024

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

syscall::open:entry
/pid != $pid/
{
    self->file_name_open = copyinstr(arg0);
}

syscall::open:return
/pid != $pid/
{
	printf("%s {\"event\": \"%s:%s:%s:\", \"time\": %d, \"pid\": %d, \"ppid\": %d, \"tid\": %d, \"uid\": %d, \"exec\": \"%s\", \"path\": \"%s\", \"fd\": %d}\n",
	    comma, probeprov, probemod, probefunc, walltimestamp, pid, ppid, tid, uid, execname, fds[arg0].fi_pathname, arg0);
	comma=",";
}

syscall::openat:entry
/pid != $pid/
{
    self->file_name_openat = copyinstr(arg1);
}

syscall::openat:return
/pid != $pid/
{
	printf("%s {\"event\": \"%s:%s:%s:\", \"time\": %d, \"pid\": %d, \"ppid\": %d, \"tid\": %d, \"uid\": %d, \"exec\": \"%s\", \"path\": \"%s\", \"fd\": %d}\n",
	    comma, probeprov, probemod, probefunc, walltimestamp, pid, ppid, tid, uid, execname, fds[arg0].fi_pathname, arg0);
	comma=",";
}

syscall::rename:entry
/pid != $pid/
{
	printf("%s {\"event\": \"%s:%s:%s:\", \"time\": %d, \"pid\": %d, \"ppid\": %d, \"tid\": %d, \"uid\": %d, \"exec\": \"%s\", \"path\": \"%s\", \"new_path\": \"%s\" }\n",
	    comma, probeprov, probemod, probefunc, walltimestamp, pid, ppid, tid, uid, execname, copyinstr(arg0), copyinstr(arg1));
	comma=",";
}

syscall::renameat:entry
/pid != $pid/
{
	printf("%s {\"event\": \"%s:%s:%s:\", \"time\": %d, \"pid\": %d, \"ppid\": %d, \"tid\": %d, \"uid\": %d, \"exec\": \"%s\", \"path\": \"%s\", \"new_path\": \"%s\" }\n",
	    comma, probeprov, probemod, probefunc, walltimestamp, pid, ppid, tid, uid, execname, copyinstr(arg1), copyinstr(arg3));
	comma=",";
}

syscall::close:entry
/pid != $pid/
{
	printf("%s {\"event\": \"%s:%s:%s:\", \"time\": %d, \"pid\": %d, \"ppid\": %d, \"tid\": %d, \"uid\": %d, \"exec\": \"%s\", \"path\": \"%s\", \"fd\": %d }\n",
	    comma, probeprov, probemod, probefunc, walltimestamp, pid, ppid, tid, uid, execname, fds[arg0].fi_pathname, arg0);
	comma=",";
}

syscall::dup*:entry
/pid != $pid/
{
    self->file_desc_dup = arg0;
}

syscall::dup*:return
/pid != $pid/
{
	printf("%s {\"event\": \"%s:%s:%s:\", \"time\": %d, \"pid\": %d, \"ppid\": %d, \"tid\": %d, \"uid\": %d, \"exec\": \"%s\", \"new_fd\": %d, \"fd\": %d }\n",
	    comma, probeprov, probemod, probefunc, walltimestamp, pid, ppid, tid, uid, execname, arg0, self->file_desc_dup);
	comma=",";
}

syscall::mmap:entry
/arg4 != -1 && pid != $pid && execname != "sshd" && execname != "tmux" && execname != "moused"/
{
	printf("%s {\"event\": \"%s:%s:%s:\", \"time\": %d, \"pid\": %d, \"tid\": %d, \"uid\": %d, \"exec\": \"%s\", \"fd\": %d, \"path\": \"%s\" }\n",
	    comma, probeprov, probemod, probefunc, walltimestamp, pid, tid, uid, execname, arg4, fds[arg4].fi_pathname);
	comma=",";
}

syscall::read:entry,syscall::write:entry,
syscall::pread:entry,syscall::pwrite:entry,
syscall::readv:entry,syscall::writev:entry,
syscall::preadv:entry,syscall::pwritev:entry
/pid != $pid && execname != "sshd" && execname != "tmux" && execname != "moused"/
{
	printf("%s {\"event\": \"%s:%s:%s:\", \"time\": %d, \"pid\": %d, \"ppid\": %d, \"tid\": %d, \"uid\": %d, \"exec\": \"%s\", \"fd\": %d, \"path\": \"%s\" }\n",
	    comma, probeprov, probemod, probefunc, walltimestamp, pid, ppid, tid, uid, execname, arg0, fds[arg0].fi_pathname);
	comma=",";
}

syscall::execve:entry
/pid != $pid/
{
	printf("%s {\"event\": \"%s:%s:%s:\", \"time\": %d, \"pid\": %d, \"tid\": %d, \"ppid\": %d, \"uid\": %d, \"exec\": \"%s\", \"new_exec\": \"%s\"}\n",
	    comma, probeprov, probemod, probefunc, walltimestamp, pid, tid, ppid, uid, execname, copyinstr(arg0));
	comma=",";
}

syscall::fork:return,syscall::rfork:return,syscall::vfork:return
/pid != $pid/
{
	printf("%s {\"event\": \"%s:%s:%s:\", \"time\": %d, \"pid\": %d, \"ppid\": %d, \"tid\": %d, \"uid\": %d, \"exec\": \"%s\", \"new_pid\": %d }\n",
	    comma, probeprov, probemod, probefunc, walltimestamp, pid, ppid, tid, uid, execname, arg0);
	comma=",";
}

syscall::exit:entry
/pid != $pid/
{
	printf("%s {\"event\": \"%s:%s:%s:\", \"time\": %d, \"pid\": %d, \"ppid\": %d, \"tid\": %d, \"uid\": %d, \"exec\": \"%s\"}\n",
	    comma, probeprov, probemod, probefunc, walltimestamp, pid, ppid, tid, uid, execname);
	comma=",";
}

syscall::connect*:entry
{
	/* assume this is sockaddr_in until we can examine family */
	this->s = (struct sockaddr_in *)copyin(arg1, sizeof (struct sockaddr));
	this->f = this->s->sin_family;
}

syscall::connect*:entry
/this->f == af_inet/
{
	self->family = this->f;
	self->port = ntohs(this->s->sin_port);
	self->address = inet_ntop(self->family, (void *)&this->s->sin_addr);
	self->start = timestamp;
}

syscall::connect*:entry
/this->f == af_inet6/
{
	/* refetch for sockaddr_in6 */
	this->s6 = (struct sockaddr_in6 *)copyin(arg1,
	    sizeof (struct sockaddr_in6));
	self->family = this->f;
	self->port = ntohs(this->s6->sin6_port);
	self->address = inet_ntoa6((in6_addr_t *)&this->s6->sin6_addr);
	self->start = timestamp;
}

syscall::connect*:return
/self->start/
{
	this->delta = (timestamp - self->start) / 1000;
	printf("%s {\"event\": \"%s:%s:%s:\", \"time\": %d, \"pid\": %d, \"ppid\": %d, \"tid\": %d, \"uid\": %d, \"exec\": \"%s\", \"family\": %d, \"address\": \"%s\", \"port\": %d, \"err\": %d}\n",
	    comma, probeprov, probemod, probefunc, walltimestamp, pid, ppid, tid, uid, execname, self->family, self->address, self->port, errno);
	comma=",";
	self->family = 0;
	self->address = 0;
	self->port = 0;
	self->start = 0;
}

syscall::accept*:entry
{
	self->sa = arg1;
	self->start = timestamp;
}

syscall::accept*:return
/self->sa/
{
	this->delta = (timestamp - self->start) / 1000;
	/* assume this is sockaddr_in until we can examine family */
	this->s = (struct sockaddr_in *)copyin(self->sa,
	    sizeof (struct sockaddr_in));
	this->f = this->s->sin_family;
}

syscall::accept*:return
/this->f == af_inet/
{
	this->port = ntohs(this->s->sin_port);
	this->address = inet_ntoa((in_addr_t *)&this->s->sin_addr);
	printf("%s {\"event\": \"%s:%s:%s:\", \"time\": %d, \"pid\": %d, \"ppid\": %d, \"tid\": %d, \"uid\": %d, \"exec\": \"%s\", \"family\": %d, \"address\": \"%s\", \"port\": %d, \"err\": %d}\n",
	    comma, probeprov, probemod, probefunc, walltimestamp, pid, ppid, tid, uid, execname, this->f, this->address, this->port, errno);
	comma=",";
}

syscall::accept*:return
/this->f == af_inet6/
{
	/* refetch for sockaddr_in6 */
	this->s6 = (struct sockaddr_in6 *)copyin(self->sa,
	    sizeof (struct sockaddr_in6));
	this->port = ntohs(this->s6->sin6_port);
	this->address = inet_ntoa6((in6_addr_t *)&this->s6->sin6_addr);
	printf("%s {\"event\": \"%s:%s:%s:\", \"time\": %d, \"pid\": %d, \"ppid\": %d, \"tid\": %d, \"uid\": %d, \"exec\": \"%s\", \"family\": %d, \"address\": \"%s\", \"port\": %d, \"err\": %d}\n",
	    comma, probeprov, probemod, probefunc, walltimestamp, pid, ppid, tid, uid, execname, this->f, this->address, this->port, errno);
	comma=",";
}

syscall::accept*:return
/self->start/
{
	self->sa = 0; self->start = 0;
}

syscall:freebsd:setuid:entry, syscall:freebsd:setgid:entry,
syscall:freebsd32:setuid:entry, syscall:freebsd32:setgid:entry,
syscall:freebsd:seteuid:entry, syscall:freebsd:setegid:entry,
syscall:freebsd32:seteuid:entry, syscall:freebsd32:setegid:entry
/pid != $pid/
{
	printf("%s {\"event\": \"%s:%s:%s:\", \"time\": %d, \"pid\": %d, \"ppid\": %d, \"tid\": %d, \"uid\": %d, \"exec\": \"%s\", \"new_id\": %d }\n",
	    comma, probeprov, probemod, probefunc, walltimestamp, pid, ppid, tid, uid, execname, args[0]);
	comma=",";
}

syscall:freebsd:setreuid:entry, syscall:freebsd:setregid:entry,
syscall:freebsd32:setreuid:entry, syscall:freebsd32:setregid:entry
/pid != $pid/
{
	printf("%s {\"event\": \"%s:%s:%s:\", \"time\": %d, \"pid\": %d, \"ppid\": %d, \"tid\": %d, \"uid\": %d, \"exec\": \"%s\", \"new_real_id\": %d, \"new_effective_id\": %d }\n",
	    comma, probeprov, probemod, probefunc, walltimestamp, pid, ppid, tid, uid, execname, args[0], args[1]);
	comma=",";
}

syscall:freebsd:setresuid:entry, syscall:freebsd:setresgid:entry,
syscall:freebsd32:setresuid:entry, syscall:freebsd32:setresgid:entry
/pid != $pid/
{
	printf("%s {\"event\": \"%s:%s:%s:\", \"time\": %d, \"pid\": %d, \"ppid\": %d, \"tid\": %d, \"uid\": %d, \"exec\": \"%s\", \"new_real_id\": %d, \"new_effective_id\": %d, \"new_saved_id\": %d }\n",
	    comma, probeprov, probemod, probefunc, walltimestamp, pid, ppid, tid, uid, execname, args[0], args[1], args[2]);
	comma=",";
}

/* For some reason, the syscall pipe probe doesn't provide the arguements on entry
syscall:freebsd:pipe:entry, syscall:freebsd32:pipe:entry,
*/
syscall:freebsd:pipe2:entry, syscall:freebsd32:pipe2:entry
/pid != $pid/
{
	printf("%s {\"event\": \"%s:%s:%s:\", \"time\": %d, \"pid\": %d, \"ppid\": %d, \"tid\": %d, \"uid\": %d, \"exec\": \"%s\", \"read_fd\": %d, \"write_fd\": %d }\n",
	    comma, probeprov, probemod, probefunc, walltimestamp, pid, ppid, tid, uid, execname, args[0][0], args[0][1]);
	comma=",";
}

syscall::recvfrom:entry
/pid != $pid/
{
	printf("%s {\"event\": \"%s:%s:%s:\", \"time\": %d, \"pid\": %d, \"ppid\": %d, \"tid\": %d, \"uid\": %d, \"exec\": \"%s\", \"socket\": %d, \"flags\": %d }\n",
	    comma, probeprov, probemod, probefunc, walltimestamp, pid, ppid, tid, uid, execname, args[0], args[3]);
	comma=",";
}

syscall::recvmsg:entry
/pid != $pid/
{
	printf("%s {\"event\": \"%s:%s:%s:\", \"time\": %d, \"pid\": %d, \"ppid\": %d, \"tid\": %d, \"uid\": %d, \"exec\": \"%s\", \"socket\": %d, \"flags\": %d }\n",
	    comma, probeprov, probemod, probefunc, walltimestamp, pid, ppid, tid, uid, execname, args[0], args[2]);
	comma=",";
}

syscall:freebsd:chdir:entry, syscall:freebsd32:chdir:entry
/pid != $pid/
{
	printf("%s {\"event\": \"%s:%s:%s:\", \"time\": %d, \"pid\": %d, \"ppid\": %d, \"tid\": %d, \"uid\": %d, \"exec\": \"%s\", \"path\": \"%s\" }\n",
	    comma, probeprov, probemod, probefunc, walltimestamp, pid, ppid, tid, uid, execname, copyinstr(arg0));
	comma=",";
}

syscall::fchdir:entry
/pid != $pid/
{
	printf("%s {\"event\": \"%s:%s:%s:\", \"time\": %d, \"pid\": %d, \"ppid\": %d, \"tid\": %d, \"uid\": %d, \"exec\": \"%s\", \"path\": \"%s\" }\n",
	    comma, probeprov, probemod, probefunc, walltimestamp, pid, ppid, tid, uid, execname, fds[arg0].fi_pathname);
	comma=",";
}

syscall:freebsd:chmod:entry,
syscall:freebsd:lchmod:entry,
syscall:freebsd32:chmod:entry,
syscall:freebsd32:lchmod:entry
/pid != $pid/
{
	printf("%s {\"event\": \"%s:%s:%s:\", \"time\": %d, \"pid\": %d, \"ppid\": %d, \"tid\": %d, \"uid\": %d, \"exec\": \"%s\", \"path\": \"%s\", \"mode\": %d }\n",
	    comma, probeprov, probemod, probefunc, walltimestamp, pid, ppid, tid, uid, execname, copyinstr(arg0), args[1]);
	comma=",";
}

syscall:freebsd:fchmod:entry,
syscall:freebsd32:fchmod:entry
/pid != $pid/
{
	printf("%s {\"event\": \"%s:%s:%s:\", \"time\": %d, \"pid\": %d, \"ppid\": %d, \"tid\": %d, \"uid\": %d, \"exec\": \"%s\", \"path\": \"%s\", \"mode\": %d }\n",
	    comma, probeprov, probemod, probefunc, walltimestamp, pid, ppid, tid, uid, execname, fds[arg0].fi_pathname, args[1]);
	comma=",";
}

syscall:freebsd:fchmodat:entry,
syscall:freebsd32:fchmodat:entry
/pid != $pid/
{
	printf("%s {\"event\": \"%s:%s:%s:\", \"time\": %d, \"pid\": %d, \"ppid\": %d, \"tid\": %d, \"uid\": %d, \"exec\": \"%s\", \"fd\": %d, \"path\": \"%s\", \"mode\": %d }\n",
	    comma, probeprov, probemod, probefunc, walltimestamp, pid, ppid, tid, uid, execname, arg0, copyinstr(arg1), args[2]);
	comma=",";
}

syscall:freebsd:chown:entry,
syscall:freebsd:lchown:entry,
syscall:freebsd32:chown:entry,
syscall:freebsd32:lchown:entry
/pid != $pid/
{
	printf("%s {\"event\": \"%s:%s:%s:\", \"time\": %d, \"pid\": %d, \"ppid\": %d, \"tid\": %d, \"uid\": %d, \"exec\": \"%s\", \"path\": \"%s\", \"owner\": %d, \"group\": %d }\n",
	    comma, probeprov, probemod, probefunc, walltimestamp, pid, ppid, tid, uid, execname, copyinstr(arg0), args[1], args[2]);
	comma=",";
}

syscall:freebsd:fchown:entry,
syscall:freebsd32:fchown:entry
/pid != $pid/
{
	printf("%s {\"event\": \"%s:%s:%s:\", \"time\": %d, \"pid\": %d, \"ppid\": %d, \"tid\": %d, \"uid\": %d, \"exec\": \"%s\", \"path\": \"%s\", \"owner\": %d, \"group\": %d }\n",
	    comma, probeprov, probemod, probefunc, walltimestamp, pid, ppid, tid, uid, execname, fds[arg0].fi_pathname, args[1], args[2]);
	comma=",";
}

syscall:freebsd:fchownat:entry,
syscall:freebsd32:fchownat:entry
/pid != $pid/
{
	printf("%s {\"event\": \"%s:%s:%s:\", \"time\": %d, \"pid\": %d, \"ppid\": %d, \"tid\": %d, \"uid\": %d, \"exec\": \"%s\", \"fd\": %d, \"path\": \"%s\", \"owner\": %d, \"group\": %d }\n",
	    comma, probeprov, probemod, probefunc, walltimestamp, pid, ppid, tid, uid, execname, arg0, copyinstr(arg1), args[2], args[3]);
	comma=",";
}

syscall::fcntl:entry
/pid != $pid/
{
	printf("%s {\"event\": \"%s:%s:%s:\", \"time\": %d, \"pid\": %d, \"ppid\": %d, \"tid\": %d, \"uid\": %d, \"exec\": \"%s\", \"path\": \"%s\", \"cmd\": %d }\n",
	    comma, probeprov, probemod, probefunc, walltimestamp, pid, ppid, tid, uid, execname, fds[arg0].fi_pathname, args[1]);
	comma=",";
}

syscall:freebsd:link:entry,
syscall:freebsd32:link:entry
/pid != $pid/
{
	printf("%s {\"event\": \"%s:%s:%s:\", \"time\": %d, \"pid\": %d, \"ppid\": %d, \"tid\": %d, \"uid\": %d, \"exec\": \"%s\", \"path\": \"%s\", \"new_path\": \"%s\" }\n",
	    comma, probeprov, probemod, probefunc, walltimestamp, pid, ppid, tid, uid, execname, fds[arg0].fi_pathname, fds[arg1].fi_pathname);
	comma=",";
}

syscall:freebsd:linkat:entry,
syscall:freebsd32:linkat:entry
/pid != $pid/
{
	printf("%s {\"event\": \"%s:%s:%s:\", \"time\": %d, \"pid\": %d, \"ppid\": %d, \"tid\": %d, \"uid\": %d, \"exec\": \"%s\", \"fd\": %d, \"path\": \"%s\", \"new_fd\": %d, \"new_path\": \"%s\" }\n",
	    comma, probeprov, probemod, probefunc, walltimestamp, pid, ppid, tid, uid, execname, arg0, fds[arg1].fi_pathname, arg2, fds[arg3].fi_pathname);
	comma=",";
}

syscall::lseek:entry
/pid != $pid/
{
	printf("%s {\"event\": \"%s:%s:%s:\", \"time\": %d, \"pid\": %d, \"ppid\": %d, \"tid\": %d, \"uid\": %d, \"exec\": \"%s\", \"path\": \"%s\", \"offset\": %d, \"whence\": %d}\n",
	    comma, probeprov, probemod, probefunc, walltimestamp, pid, ppid, tid, uid, execname, fds[arg0].fi_pathname, arg1, arg2);
	comma=",";
}

syscall:freebsd:mkdir:entry,
syscall:freebsd32:mkdir:entry
/pid != $pid/
{
	printf("%s {\"event\": \"%s:%s:%s:\", \"time\": %d, \"pid\": %d, \"ppid\": %d, \"tid\": %d, \"uid\": %d, \"exec\": \"%s\", \"path\": \"%s\", \"mode\": %d }\n",
	    comma, probeprov, probemod, probefunc, walltimestamp, pid, ppid, tid, uid, execname, copyinstr(arg0), arg1);
	comma=",";
}

syscall:freebsd:mkdirat:entry,
syscall:freebsd32:mkdirat:entry
/pid != $pid/
{
	printf("%s {\"event\": \"%s:%s:%s:\", \"time\": %d, \"pid\": %d, \"ppid\": %d, \"tid\": %d, \"uid\": %d, \"exec\": \"%s\", \"fd\": %d, \"path\": \"%s\", \"mode\": %d }\n",
	    comma, probeprov, probemod, probefunc, walltimestamp, pid, ppid, tid, uid, execname, arg0, copyinstr(arg1), arg2);
	comma=",";
}

syscall:freebsd:rename:entry,
syscall:freebsd32:rename:entry
/pid != $pid/
{
	printf("%s {\"event\": \"%s:%s:%s:\", \"time\": %d, \"pid\": %d, \"ppid\": %d, \"tid\": %d, \"uid\": %d, \"exec\": \"%s\", \"path\": \"%s\", \"new_path\": \"%s\" }\n",
	    comma, probeprov, probemod, probefunc, walltimestamp, pid, ppid, tid, uid, execname, copyinstr(arg0), copyinstr(arg1));
	comma=",";
}

syscall:freebsd:renameat:entry,
syscall:freebsd32:renameat:entry
/pid != $pid/
{
	printf("%s {\"event\": \"%s:%s:%s:\", \"time\": %d, \"pid\": %d, \"ppid\": %d, \"tid\": %d, \"uid\": %d, \"exec\": \"%s\", \"fd\": %d, \"path\": \"%s\", \"new_fd\": %d, \"new_path\": \"%s\" }\n",
	    comma, probeprov, probemod, probefunc, walltimestamp, pid, ppid, tid, uid, execname, arg0, fds[arg1].fi_pathname, arg2, fds[arg3].fi_pathname);
	comma=",";
}

syscall:freebsd:rmdir:entry,
syscall:freebsd32:rmdir:entry
/pid != $pid/
{
	printf("%s {\"event\": \"%s:%s:%s:\", \"time\": %d, \"pid\": %d, \"ppid\": %d, \"tid\": %d, \"uid\": %d, \"exec\": \"%s\", \"path\": \"%s\" }\n",
	    comma, probeprov, probemod, probefunc, walltimestamp, pid, ppid, tid, uid, execname, copyinstr(arg0));
	comma=",";
}

syscall:freebsd:sendto:entry,
syscall:freebsd32:sendto:entry
/pid != $pid/
{
	printf("%s {\"event\": \"%s:%s:%s:\", \"time\": %d, \"pid\": %d, \"ppid\": %d, \"tid\": %d, \"uid\": %d, \"exec\": \"%s\", \"socket\": %d, \"flags\": %d }\n",
	    comma, probeprov, probemod, probefunc, walltimestamp, pid, ppid, tid, uid, execname, args[0], args[2]);
	comma=",";
}

syscall::sendmsg:entry
/pid != $pid/
{
	printf("%s {\"event\": \"%s:%s:%s:\", \"time\": %d, \"pid\": %d, \"ppid\": %d, \"tid\": %d, \"uid\": %d, \"exec\": \"%s\", \"socket\": %d, \"flags\": %d }\n",
	    comma, probeprov, probemod, probefunc, walltimestamp, pid, ppid, tid, uid, execname, args[0], args[2]);
	comma=",";
}

syscall::sigaction:entry
/pid != $pid/
{
	printf("%s {\"event\": \"%s:%s:%s:\", \"time\": %d, \"pid\": %d, \"ppid\": %d, \"tid\": %d, \"uid\": %d, \"exec\": \"%s\", \"signal\": %d, \"act\": %d, \"flags\": %d,  \"oact\": %d }\n",
	    comma, probeprov, probemod, probefunc, walltimestamp, pid, ppid, tid, uid, execname, args[0], arg1, arg1 > 0 ? args[1]->sa_flags : 0, arg2);
	comma=",";
}

syscall:freebsd:socket:entry,
syscall:freebsd32:socket:entry
/pid != $pid/
{
	printf("%s {\"event\": \"%s:%s:%s:\", \"time\": %d, \"pid\": %d, \"ppid\": %d, \"tid\": %d, \"uid\": %d, \"exec\": \"%s\", \"domain\": %d, \"type\": %d, \"signal\": %d }\n",
	    comma, probeprov, probemod, probefunc, walltimestamp, pid, ppid, tid, uid, execname, args[0], args[1], args[2]);
	comma=",";
}

syscall:freebsd:socketpair:entry,
syscall:freebsd32:socketpair:entry
/pid != $pid/
{
    self->domain=args[0];
    self->type=args[1];
    self->signal=args[2];
    self->sds=arg3;
	comma=",";
}

syscall:freebsd:socketpair:return,
syscall:freebsd32:socketpair:return
/pid != $pid/
{
    self->sds2=(int *) copyin(self->sds, sizeof(int[2]));
	printf("%s {\"event\": \"%s:%s:%s:\", \"time\": %d, \"pid\": %d, \"ppid\": %d, \"tid\": %d, \"uid\": %d, \"exec\": \"%s\", \"domain\": %d, \"type\": %d, \"signal\": %d, \"new_socket\": %d, \"new_socket2\": %d }\n",
	    comma, probeprov, probemod, probefunc, walltimestamp, pid, ppid, tid, uid, execname, self->domain, self->type, self->signal, self->sds2[0], self->sds2[1]);
	comma=",";
}

syscall::symlink:entry
/pid != $pid/
{
	printf("%s {\"event\": \"%s:%s:%s:\", \"time\": %d, \"pid\": %d, \"ppid\": %d, \"tid\": %d, \"uid\": %d, \"exec\": \"%s\", \"path\": \"%s\", \"new_path\": \"%s\" }\n",
	    comma, probeprov, probemod, probefunc, walltimestamp, pid, ppid, tid, uid, execname, copyinstr(arg0), copyinstr(arg1));
	comma=",";
}

syscall:freebsd:symlinkat:entry,
syscall:freebsd32:symlinkat:entry
/pid != $pid/
{
	printf("%s {\"event\": \"%s:%s:%s:\", \"time\": %d, \"pid\": %d, \"ppid\": %d, \"tid\": %d, \"uid\": %d, \"exec\": \"%s\", \"path\": \"%s\", \"fd\": %d, \"new_path\": \"%s\" }\n",
	    comma, probeprov, probemod, probefunc, walltimestamp, pid, ppid, tid, uid, execname, copyinstr(arg0), args[1], copyinstr(arg2));
	comma=",";
}

syscall::truncate:entry
/pid != $pid/
{
	printf("%s {\"event\": \"%s:%s:%s:\", \"time\": %d, \"pid\": %d, \"ppid\": %d, \"tid\": %d, \"uid\": %d, \"exec\": \"%s\", \"path\": \"%s\", \"length\": %d }\n",
	    comma, probeprov, probemod, probefunc, walltimestamp, pid, ppid, tid, uid, execname, copyinstr(arg0), args[1]);
	comma=",";
}

syscall::ftruncate:entry
/pid != $pid/
{
	printf("%s {\"event\": \"%s:%s:%s:\", \"time\": %d, \"pid\": %d, \"ppid\": %d, \"tid\": %d, \"uid\": %d, \"exec\": \"%s\", \"path\": \"%s\", \"length\": %d }\n",
	    comma, probeprov, probemod, probefunc, walltimestamp, pid, ppid, tid, uid, execname, fds[arg0].fi_pathname, args[1]);
	comma=",";
}

syscall:freebsd:umask:entry,
syscall:freebsd32:umask:entry
/pid != $pid/
{
    self->new_mask = args[0];
}

syscall::unlink:entry
/pid != $pid/
{
	printf("%s {\"event\": \"%s:%s:%s:\", \"time\": %d, \"pid\": %d, \"ppid\": %d, \"tid\": %d, \"uid\": %d, \"exec\": \"%s\", \"path\": \"%s\" }\n",
	    comma, probeprov, probemod, probefunc, walltimestamp, pid, ppid, tid, uid, execname, copyinstr(arg0));
	comma=",";
}

syscall::unlinkat:entry
/pid != $pid/
{
	printf("%s {\"event\": \"%s:%s:%s:\", \"time\": %d, \"pid\": %d, \"ppid\": %d, \"tid\": %d, \"uid\": %d, \"exec\": \"%s\", \"fd\": %d, \"path\": \"%s\", \"mode\": %d }\n",
	    comma, probeprov, probemod, probefunc, walltimestamp, pid, ppid, tid, uid, execname, arg0, copyinstr(arg1), arg2);
	comma=",";
}

syscall::utimes:entry,
syscall::lutimes:entry
/pid != $pid && arg1 == 0/
{
	printf("%s {\"event\": \"%s:%s:%s:\", \"time\": %d, \"pid\": %d, \"ppid\": %d, \"tid\": %d, \"uid\": %d, \"exec\": \"%s\", \"path\": \"%s\" }\n",
	    comma, probeprov, probemod, probefunc, walltimestamp, pid, ppid, tid, uid, execname, copyinstr(arg0));
	comma=",";
}

syscall::utimes:entry,
syscall::lutimes:entry
/pid != $pid && arg1 != 0/
{
    self->times=args[1];
	printf("%s {\"event\": \"%s:%s:%s:\", \"time\": %d, \"pid\": %d, \"ppid\": %d, \"tid\": %d, \"uid\": %d, \"exec\": \"%s\", \"path\": \"%s\", \"create_time\": %d, \"mod_time\": %d }\n",
	    comma, probeprov, probemod, probefunc, walltimestamp, pid, ppid, tid, uid, execname, copyinstr(arg0), self->times[0].tv_sec*1000000+self->times[0].tv_usec, self->times[1].tv_sec*1000000+self->times[1].tv_usec);
	comma=",";
}

syscall::futimes:entry
/pid != $pid && arg1 == 0/
{
	printf("%s {\"event\": \"%s:%s:%s:\", \"time\": %d, \"pid\": %d, \"ppid\": %d, \"tid\": %d, \"uid\": %d, \"exec\": \"%s\", \"path\": \"%s\" }\n",
	    comma, probeprov, probemod, probefunc, walltimestamp, pid, ppid, tid, uid, execname, fds[arg0].fi_pathname);
	comma=",";
}

syscall::futimes:entry
/pid != $pid && arg1 != 0/
{
    self->times=args[1];
	printf("%s {\"event\": \"%s:%s:%s:\", \"time\": %d, \"pid\": %d, \"ppid\": %d, \"tid\": %d, \"uid\": %d, \"exec\": \"%s\", \"path\": \"%s\", \"create_time\": %d, \"mod_time\": %d }\n",
	    comma, probeprov, probemod, probefunc, walltimestamp, pid, ppid, tid, uid, execname, fds[arg0].fi_pathname, self->times[0].tv_sec*1000000+self->times[0].tv_usec, self->times[1].tv_sec*1000000+self->times[1].tv_usec);
	comma=",";
}

syscall::futimesat:entry
/pid != $pid && arg2 == 0/
{
	printf("%s {\"event\": \"%s:%s:%s:\", \"time\": %d, \"pid\": %d, \"ppid\": %d, \"tid\": %d, \"uid\": %d, \"exec\": \"%s\", \"fd\": %d, \"path\": \"%s\" }\n",
	    comma, probeprov, probemod, probefunc, walltimestamp, pid, ppid, tid, uid, execname, arg0, copyinstr(arg1));
	comma=",";
}

syscall::futimesat:entry
/pid != $pid && arg2 != 0/
{
    self->times=args[2];
	printf("%s {\"event\": \"%s:%s:%s:\", \"time\": %d, \"pid\": %d, \"ppid\": %d, \"tid\": %d, \"uid\": %d, \"exec\": \"%s\", \"fd\": %d, \"path\": \"%s\", \"create_time\": %d, \"mod_time\": %d }\n",
	    comma, probeprov, probemod, probefunc, walltimestamp, pid, ppid, tid, uid, execname, arg0, copyinstr(arg1), self->times[0].tv_sec*1000000+self->times[0].tv_usec, self->times[1].tv_sec*1000000+self->times[1].tv_usec);
	comma=",";
}
