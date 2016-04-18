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
	printf("%s {\"event\": \"%s:%s:%s:\", \"time\": %d, \"pid\": %d, \"tid\": %d, \"uid\": %d, \"exec\": \"%s\", \"path\": \"%s\", \"fd\": %d}\n",
	    comma, probeprov, probemod, probefunc, walltimestamp, pid, tid, uid, execname, self->file_name_open, arg0);
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
	printf("%s {\"event\": \"%s:%s:%s:\", \"time\": %d, \"pid\": %d, \"tid\": %d, \"uid\": %d, \"exec\": \"%s\", \"path\": \"%s\", \"fd\": %d}\n",
	    comma, probeprov, probemod, probefunc, walltimestamp, pid, tid, uid, execname, self->file_name_openat, arg0);
	comma=",";
}

syscall::close:entry
/pid != $pid/
{
	printf("%s {\"event\": \"%s:%s:%s:\", \"time\": %d, \"pid\": %d, \"tid\": %d, \"uid\": %d, \"exec\": \"%s\", \"fd\": %d }\n",
	    comma, probeprov, probemod, probefunc, walltimestamp, pid, tid, uid, execname, arg0);
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
	printf("%s {\"event\": \"%s:%s:%s:\", \"time\": %d, \"pid\": %d, \"tid\": %d, \"uid\": %d, \"exec\": \"%s\", \"new_fd\": %d, \"fd\": %d }\n",
	    comma, probeprov, probemod, probefunc, walltimestamp, pid, tid, uid, execname, arg0, self->file_desc_dup);
	comma=",";
}

syscall::read:entry,syscall::write:entry,
syscall::pread:entry,syscall::pwrite:entry,
syscall::readv:entry,syscall::writev:entry,
syscall::preadv:entry,syscall::pwritev:entry
/pid != $pid && execname != "sshd" && execname != "tmux"/
{
	printf("%s {\"event\": \"%s:%s:%s:\", \"time\": %d, \"pid\": %d, \"tid\": %d, \"uid\": %d, \"exec\": \"%s\", \"fd\": %d, \"path\": \"%s\" }\n",
	    comma, probeprov, probemod, probefunc, walltimestamp, pid, tid, uid, execname, arg0, fds[arg0].fi_pathname);
	comma=",";
}

syscall::execve:entry
/pid != $pid/
{
	printf("%s {\"event\": \"%s:%s:%s:\", \"time\": %d, \"pid\": %d, \"tid\": %d, \"ppid\": %d, \"uid\": %d, \"exec\": \"%s\"}\n",
	    comma, probeprov, probemod, probefunc, walltimestamp, pid, tid, curpsinfo->pr_ppid, uid, copyinstr(arg0));
	comma=",";
}

syscall::fork:return,syscall::rfork:return,syscall::vfork:return
/pid != $pid/
{
	printf("%s {\"event\": \"%s:%s:%s:\", \"time\": %d, \"pid\": %d, \"tid\": %d, \"uid\": %d, \"exec\": \"%s\", \"new_pid\": %d }\n",
	    comma, probeprov, probemod, probefunc, walltimestamp, pid, tid, uid, execname, arg0);
	comma=",";
}

syscall::exit:entry
/pid != $pid/
{
	printf("%s {\"event\": \"%s:%s:%s:\", \"time\": %d, \"pid\": %d, \"tid\": %d, \"uid\": %d, \"exec\": \"%s\"}\n",
	    comma, probeprov, probemod, probefunc, walltimestamp, pid, tid, uid, execname);
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
	printf("%s {\"event\": \"%s:%s:%s:\", \"time\": %d, \"pid\": %d, \"tid\": %d, \"uid\": %d, \"exec\": \"%s\", \"family\": %d, \"address\": \"%s\", \"port\": %d, \"err\": %d}\n",
	    comma, probeprov, probemod, probefunc, walltimestamp, pid, tid, uid, execname, self->family, self->address, self->port, errno);
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
	printf("%s {\"event\": \"%s:%s:%s:\", \"time\": %d, \"pid\": %d, \"tid\": %d, \"uid\": %d, \"exec\": \"%s\", \"family\": %d, \"address\": \"%s\", \"port\": %d, \"err\": %d}\n",
	    comma, probeprov, probemod, probefunc, walltimestamp, pid, tid, uid, execname, this->f, this->address, this->port, errno);
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
	printf("%s {\"event\": \"%s:%s:%s:\", \"time\": %d, \"pid\": %d, \"tid\": %d, \"uid\": %d, \"exec\": \"%s\", \"family\": %d, \"address\": \"%s\", \"port\": %d, \"err\": %d}\n",
	    comma, probeprov, probemod, probefunc, walltimestamp, pid, tid, uid, execname, this->f, this->address, this->port, errno);
	comma=",";
}

syscall::accept*:return
/self->start/
{
	self->sa = 0; self->start = 0;
}
