//#include <linux/bpf.h>

#define SEC(NAME) __attribute__((section(NAME),  used))

/* SECTION_NAME_PLACEHOLDER */
int foo(__attribute__((unused)) void *ctx)
{
	return 1;
}

char _license[] __attribute__((section("license"), used)) = "GPL";
