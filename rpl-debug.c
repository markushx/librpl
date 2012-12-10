
#include <netinet/in.h>

#include "rpl.h"

void
rpl_debug_ipaddr_print(struct in6_addr *addr)
{
  uint16_t a;
  unsigned int i;
  int f;
  for(i = 0, f = 0; i < sizeof(struct in6_addr); i += 2) {
    a = (addr->s6_addr[i] << 8) + addr->s6_addr[i + 1];
    if(a == 0 && f >= 0) {
      if(f++ == 0) {
        PRINTA("::");
      }
    } else {
      if(f > 0) {
        f = -1;
      } else if(i > 0) {
        PRINTA(":");
      }
      PRINTA("%x", a);
    }
  }
}
