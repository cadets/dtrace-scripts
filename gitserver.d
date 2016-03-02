#!/usr/sbin/dtrace -s

#pragma D option quiet

BEGIN {
	printf("[\n");
	comma=" ";
}

END {
  printf("]\n");
}

/* Used for git pull, fetch, and git clone 
 * So far, git pull and git fetch appear identically.
 * git clone will also show this, but there are additional git calls that
 * indicate it's actually a clone.
 */
syscall::exec*:
/execname == "git-upload-pack"/
{
	printf("%s {\"event\": \"%s:%s\", \"time\": %d, \"pid\": %d, \"tid\": %d, \"uid\": %d, \"exec\": \"%s\", \"meaning\": \"%s\"}\n",
	    comma, "git", "upload-pack", walltimestamp, pid, tid, uid, execname, "pull, fetch, or clone");
	comma=",";
}

/* Used for git push */
syscall::exec*:
/execname == "git-receive-pack"/
{
	printf("%s {\"event\": \"%s:%s\", \"time\": %d, \"pid\": %d, \"tid\": %d, \"uid\": %d, \"exec\": \"%s\", \"meaning\": \"%s\"}\n",
	    comma, "git", "receive-pack", walltimestamp, pid, tid, uid, execname, "push");
	comma=",";
}

/* Some of the sshd's show the connecting user - on git connections, shows up
 * as username@notty in the curpsinfo->pr_psargs
 */
syscall::exec*:
/execname == "sshd"/
{
	printf("%s {\"event\": \"%s:%s\", \"time\": %d, \"pid\": %d, \"tid\": %d, \"uid\": %d, \"exec\": \"%s\", \"user\": \"%s\"}\n",
	    comma, "ssh", "incoming", walltimestamp, pid, tid, uid, execname, stringof(curpsinfo->pr_psargs));
	comma=",";
}

/* What does the git executable have to say
 */
syscall::exec*:
/execname == "git"/
{
	printf("%s {\"event\": \"%s:%s\", \"time\": %d, \"pid\": %d, \"tid\": %d, \"uid\": %d, \"exec\": \"%s\", \"details\": \"%s\"}\n",
	    comma, "git", "command", walltimestamp, pid, tid, uid, execname, stringof(curpsinfo->pr_psargs));
	comma=",";
}


