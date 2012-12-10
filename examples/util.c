
#include <stdio.h>
#include <errno.h>

#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <netinet/in.h>

#include "util.h"

void
print_addr(struct in6_addr *addr, char *str)
{
	const char *res;

	/* XXX: overflows 'str' if it isn't big enough */
	res = inet_ntop(AF_INET6, (void *)addr, str, INET6_ADDRSTRLEN);

	if (res == NULL)
	{
	  fprintf(stderr, "print_addr: inet_ntop: %s", strerror(errno));
		strcpy(str, "[invalid address]");
	}
}
