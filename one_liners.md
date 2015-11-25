DTrace One Liners
=================

Filesystem
----------

Processes opening /etc/hosts:

~~~
sudo dtrace -q -n 'syscall::open*:entry /copyinstr(arg0) == "/etc/hosts"/ { printf("At %Y %s file opened by PID %d UID %d using %s\n", walltimestamp, copyinstr(arg0), pid, uid, execname); }'
~~~

~~~
At 2015 Nov 14 21:07:14 /etc/hosts file opened by PID 18941 UID 1001 using vi
~~~

File opens:

~~~
sudo dtrace -q -n 'syscall::open*:entry /pid != $pid/ { printf("At %Y %s file opened by PID %d UID %d using %s\n", walltimestamp, copyinstr(arg0), pid, uid, execname); }'
~~~

~~~
At 2015 Nov 14 21:07:14 /etc/hosts file opened by PID 18941 UID 1001 using vi
~~~

File read/writes:

~~~
sudo dtrace -q -n 'syscall::read*:entry,syscall::write*:entry /pid != $pid/ { printf("At %Y %s file %s by %s\n", walltimestamp, fds[arg0].fi_pathname, probefunc, execname)}'
~~~

~~~
At 2015 Oct 17 02:22:49 /var/pkg/tmp5pybtJ file write by python2.6
At 2015 Oct 17 02:22:49 /var/pkg/cache/tmp/tmpOWNIsO/installed/catalog.attrs file read by python2.6
~~~

Files written:

~~~
sudo dtrace -n 'syscall::write:entry { @[fds[arg0].fi_pathname] = count(); }'
~~~

~~~
  /dev/pts/1                                                        1
  /dev/pts/2                                                        1
~~~

Process
-------

~~~
sudo dtrace -n 'proc:::exec-success { trace(curpsinfo->pr_psargs); }'
~~~

~~~
  1  60080                none:exec-success   /bin/sh /sbin/dhclient-script
  3  60080                none:exec-success   /bin/hostname
~~~

~~~
sudo dtrace -qn 'syscall::exec*:return { printf("%Y %s\n",walltimestamp,curpsinfo->pr_psargs); }'
~~~

~~~
  1  60080                none:exec-success   /bin/sh /sbin/dhclient-script
  3  60080                none:exec-success   /bin/hostname
~~~

~~~
sudo dtrace -n 'syscall::fork*:entry{printf("%s %d",execname,pid);}'
~~~

~~~
  2  61729                       fork:entry bash 20939
  2  61729                       fork:entry bash 20939
~~~

Function Block Tracing
----------------------

malloc:

~~~
sudo dtrace -n 'fbt::malloc:entry { trace(execname); trace(arg0); }'
~~~

~~~
 2  31971                     malloc:entry   sendmail                                        44
~~~

dtmalloc:

~~~
sudo dtrace -n 'dtmalloc::temp:malloc /execname=="csh"/ { trace(execname); trace(arg3); }'
~~~

~~~
CPU     ID                    FUNCTION:NAME
  2  63501                      temp:malloc   csh                                           1024
  2  63501                      temp:malloc   csh                                            128
~~~


PID
---

Count functions:

~~~
sudo dtrace -n 'pid1:::entry { @a[probemod,probefunc] = count(); } END { trunc(@a,10); }'
~~~

~~~
  libsystem_c.dylib                                   strlen                                                          478
  libsystem_platform.dylib                            _platform_strcmp                                                596
~~~
