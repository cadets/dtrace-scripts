#!/usr/sbin/dtrace -s

#pragma D option quiet

BEGIN {
	printf("[\n");
	comma=" ";
}

END {
  printf("]\n");
}

/* Used for Git and SSH
 * - Captures git command-line arguments
 * - Some of the sshd's show the connecting user - on git connections, shows up
 *   as username@notty in the curpsinfo->pr_psargs
 */
syscall::exec*:
/execname == "git-receive-pack" || execname == "git-upload-pack" || execname == "git" || execname == "sshd"/
{
	printf("%s {\"event\": \"%s:%s:%s:%s\", \"time\": %d, \"pid\": %d, \"tid\": %d, \"uid\": %d, \"exec\": \"%s\", \"args\": \"%s\"}\n",
	    comma, probeprov, probemod, probefunc, probename, walltimestamp, pid, tid, uid, execname, stringof(curpsinfo->pr_psargs));
	comma=",";
}
