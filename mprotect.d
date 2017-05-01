/* Defined in mman.h */

#define PROT_NONE 0x00
#define PROT_READ 0x01
#define PROT_WRITE 0x02
#define PROT_EXEC 0x04

inline string prot_table[int32_t prot] =
    prot == PROT_NONE ?		"[PROT_NONE]" :
    prot == (PROT_READ) ? 	"[PROT_READ]" :
    prot == (PROT_WRITE) ? 	"[PROT_WRITE]" :
    prot == (PROT_EXEC) ? 	"[PROT_EXEC]" :
    prot == (PROT_READ | PROT_WRITE) ? "[PROT_READ, PROT_WRITE]" :
    prot == (PROT_READ | PROT_EXEC) ? "[PROT_READ, PROT_EXEC]" :
    prot == (PROT_WRITE | PROT_EXEC) ? "[PROT_WRITE, PROT_EXEC]" :
    prot == (PROT_READ | PROT_WRITE | PROT_EXEC) ? "[PROT_READ, PROT_WRITE, PROT_EXEC]" :
    "";

    

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

syscall::mprotect:entry,
syscall::mmap:entry
{
	flags = args[2];
	printf("%s {\"event\": \"%s:%s:%s:\"", comma, probeprov, probemod, probefunc);
	printf(", \"time\": %d", walltimestamp);
	printf(", \"pid\": %d", pid);
	printf(", \"ppid\": %d",ppid);
	printf(", \"tid\": %d", tid);
	printf(", \"uid\": %d", uid);
	printf(", \"addr\": %x", arg0);
	printf(", \"len\": %d", arg1);
	printf(", \"flags\": %s", prot_table[flags]);

	printf("}\n");
	comma=",";
}
