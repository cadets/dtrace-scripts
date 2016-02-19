#!/usr/sbin/dtrace -s

#pragma D option quiet


/* Used for git pull, fetch, and git clone 
 * So far, git pull and git fetch appear identically.
 * git clone will also show this, but there are additional git calls that
 * indicate it's actually a clone.
 */
syscall::exec*:
/execname == "git-upload-pack"/
{
    printf("<proc>\n");
    printf("\t<time> %d </time>\n", walltimestamp);
    printf("\t<git>pull, fetch, or clone</git>\n");
    printf("</proc>\n\n");
}

/* Used for git push */
syscall::exec*:
/execname == "git-receive-pack"/
{
    printf("<proc>\n");
    printf("\t<time> %d </time>\n", walltimestamp);
    printf("\t<git>push</git>\n");
    printf("</proc>\n\n");
}

/* Some of the sshd's show the connecting user - on git connections, shows up
 * as username@notty in the curpsinfo->pr_psargs
 */
syscall::exec*:
/execname == "sshd"/
{
    printf("<proc>\n");
    printf("\t<time> %d </time>\n", walltimestamp);
    printf("\t<%s> %s </%s>\n", execname, stringof(curpsinfo->pr_psargs), execname);
    printf("</proc>\n\n");
}

/* What does the git executable have to say
 */
syscall::exec*:
/execname == "git"/
{
    printf("<proc>\n");
    printf("\t<time> %d </time>\n", walltimestamp);
    printf("\t<%s> %s </%s>\n", execname, stringof(curpsinfo->pr_psargs), execname);
    printf("</proc>\n\n");
}


