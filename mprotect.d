/* Defined in mman.h */

#define PROT_NONE 0x00
#define PROT_READ 0x01
#define PROT_WRITE 0x02
#define PROT_EXEC 0x04

/*
 * BEGIN and END probes
 */
BEGIN {
    printf("[\n");
    comma=" ";
}

END {
  printf("]\n");
}

syscall::mprotect:entry
{
	flags = arg2;
	printf("%s {\"event\": \"%s:%s:%s:\"", comma, probeprov, probemod, probefunc);
	printf(", \"time\": %d", walltimestamp);
	printf(", \"pid\": %d", pid);
	printf(", \"ppid\": %d",ppid);
	printf(", \"tid\": %d", tid);
	printf(", \"uid\": %d", uid);
	printf(", \"addr\": %x", arg0);
	printf(", \"len\": %d", arg1);
	printf(", \"flags\": [");
	printf("%s", flags == 0 ? "PROT_NONE" : "");
	printf("%s", flags & PROT_READ ? "PROT_READ" : "");
	printf("%s", flags & PROT_WRITE ? ", PROT_WRITE" : "");
	printf("%s", flags & PROT_EXEC ? ", PROT_EXEC" : "");
	printf("]");

	printf("}\n");
	comma=",";
}
