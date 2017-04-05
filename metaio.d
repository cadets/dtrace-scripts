#!/usr/sbin/dtrace -Cs

#pragma D option quiet

#define ARG_OBJUUID1            0x0080000000000000ULL
#define ARG_OBJUUID2            0x0100000000000000ULL
#define ARG_METAIO              0x0400000000000000ULL
#define RET_OBJUUID1            0x0000000000000001ULL
#define RET_OBJUUID2            0x0000000000000002ULL
#define RET_METAIO              0x0000000000000040ULL

#define ARG_HAS_OBJUUID1(ar)    ((ar)->ar_valid_arg & ARG_OBJUUID1)
#define ARG_HAS_OBJUUID2(ar)    ((ar)->ar_valid_arg & ARG_OBJUUID2)
#define ARG_HAS_METAIO(ar)      ((ar)->ar_valid_arg & ARG_METAIO)
#define RET_HAS_OBJUUID1(ar)    ((ar)->ar_valid_ret & RET_OBJUUID1)
#define RET_HAS_OBJUUID2(ar)    ((ar)->ar_valid_ret & RET_OBJUUID2)
#define RET_HAS_METAIO(ar)      ((ar)->ar_valid_ret & RET_METAIO)

#define QUOTED_UUID(uuid) \
	strjoin("\"", \
		strjoin( \
			uuidtostr((intptr_t) &uuid), \
			"\"") \
		)

#define UUID_OR_NULL(test, field) \
	(test(ar) ? QUOTED_UUID(ar->field) : "null")

audit:::commit
/execname != "dtrace" &&
 (ARG_HAS_METAIO(args[1]) || RET_HAS_METAIO(args[1]))/
{
	ar = args[1];

        printf("{");
	printf("\"execname\":\"%s\",", execname);
	printf("\"event\":\"%s\",", probefunc);

	printf("\"arg_objuuid1\":%s,",
		UUID_OR_NULL(ARG_HAS_OBJUUID1, ar_arg_objuuid1));
	printf("\"arg_objuuid2\":%s,",
		UUID_OR_NULL(ARG_HAS_OBJUUID2, ar_arg_objuuid2));
	printf("\"arg_metaio.mio_uuid\":%s,",
		UUID_OR_NULL(ARG_HAS_METAIO, ar_arg_metaio.mio_uuid));

	printf("\"ret_objuuid1\":%s,",
		UUID_OR_NULL(RET_HAS_OBJUUID1, ar_ret_objuuid1));
	printf("\"ret_objuuid2\":%s,",
		UUID_OR_NULL(RET_HAS_OBJUUID2, ar_ret_objuuid2));
	printf("\"ret_metaio.mio_uuid\":%s",
		UUID_OR_NULL(RET_HAS_METAIO, ar_ret_metaio.mio_uuid));

	printf("}");
}
