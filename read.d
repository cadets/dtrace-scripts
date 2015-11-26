/* Logs files that are read(). Based on:
 * https://forums.freebsd.org/threads/dtrace-howto-get-struct-fileinfo_t-from-file-descriptor.32649/
 *
 * Updated to work on recent FreeBSD. Still somewhat broken.
 */

#pragma D option quiet
#pragma D option switchrate=10hz
#pragma D option dynvarsize=16m
#pragma D option bufsize=8m

syscall:freebsd:read:entry
{
        this->fp = curthread->td_proc->p_fd->fd_files->fdt_ofiles[arg0].fde_file;
        this->vp = this->fp != 0 ? this->fp->f_vnode : 0;
        this->ts = vtimestamp;
        @c = count();
}

syscall:freebsd:read:entry
/this->vp/
{
        this->ncp = &(this->vp->v_cache_dst) != NULL ?
                this->vp->v_cache_dst.tqh_first : 0;
        this->fi_name = this->ncp ? (this->ncp->nc_name != 0 ?
                stringof(this->ncp->nc_name) : "<unknown>") : "<unknown>";
        this->mount = this->vp->v_mount; /* ptr to vfs we are in */
        this->fi_fs = this->mount != 0 ? stringof(this->mount->mnt_stat.f_fstypename)
                : "<unknown>"; /* filesystem */
        this->fi_mount = this->mount != 0 ? stringof(this->mount->mnt_stat.f_mntonname)
                : "<unknown>";
	printf("\nfi_mount: %s\n", this->fi_mount);

}

syscall:freebsd:read:entry
/* A short cut */
/this->vp == 0 || this->fi_fs == "devfs" || this->fi_fs == 0 ||
this->fi_fs == "<unknown>" || this->fi_name == "<unknown>"/
{
        this->ncp = 0;
}

syscall:freebsd:read:entry
/this->ncp/
{
        this->dvp = this->ncp->nc_dvp != NULL ?
               (&(this->ncp->nc_dvp->v_cache_dst) != NULL ?
               this->ncp->nc_dvp->v_cache_dst.tqh_first : 0) : 0;
        self->name[1] = this->dvp != 0 ? (this->dvp->nc_name != 0 ?
               stringof(this->dvp->nc_name) : "<unknown>") : "<unknown>";
}

syscall:freebsd:read:entry
/self->name[1] == "<unknown>" || this->fi_fs == "devfs" ||
this->fi_fs == 0 || this->fi_fs == "<unknown>" || self->name[1] == "/"
|| self->name[1] == 0/
{
        this->dvp = 0;
}

syscall:freebsd:read:entry
/this->dvp/
{
        this->dvp = this->dvp->nc_dvp != NULL ? (&(this->dvp->nc_dvp->v_cache_dst) != NULL
                ? this->dvp->nc_dvp->v_cache_dst.tqh_first : 0) : 0;
        self->name[2] = this->dvp != 0 ? (this->dvp->nc_name != 0 ?
                stringof(this->dvp->nc_name) : "\0") : "\0";
}

syscall:freebsd:read:entry
/this->dvp/
{
        this->dvp = this->dvp->nc_dvp != NULL ? (&(this->dvp->nc_dvp->v_cache_dst) != NULL
                ? this->dvp->nc_dvp->v_cache_dst.tqh_first : 0) : 0;
        self->name[3] = this->dvp != 0 ? (this->dvp->nc_name != 0 ?
                stringof(this->dvp->nc_name) : "\0") : "\0";
}

syscall:freebsd:read:entry
/this->fi_mount != 0/
{
        printf("%s/", this->fi_mount);
	self->fi_mount = 0
}

syscall:freebsd:read:entry
/self->name[3] != 0/
{
        printf("%s/", self->name[3]);
}

syscall:freebsd:read:entry
/self->name[2] != 0/
{
        printf("%s/", self->name[2]);
}

syscall:freebsd:read:entry
/self->name[1] != 0/
{
        printf("%s/%s\n", self->name[1], this->fi_name);
}

syscall:freebsd:read:entry
{
        self->name[1] = 0;
        self->name[2] = 0;
        self->name[3] = 0;
}

tick-10s
{
        exit(0);
}
