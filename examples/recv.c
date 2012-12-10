
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>

#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <netinet/in.h>

#include "defines.h"

extern int sock;

int
recv_dao(unsigned char *msg, struct sockaddr_in6 *addr,
	 struct in6_pktinfo **pkt_info, int *hoplimit)
{
  struct msghdr mhdr;
  struct cmsghdr *cmsg;
  struct iovec iov;
  static unsigned char *chdr = NULL;
  static unsigned int chdrlen = 0;
  int len;
  fd_set rfds;

  if( ! chdr )
    {
      chdrlen = CMSG_SPACE(sizeof(struct in6_pktinfo)) +
	CMSG_SPACE(sizeof(int));
      if ((chdr = malloc(chdrlen)) == NULL) {
	fprintf(stderr, "recv_rs_ra: malloc: %s", strerror(errno));
	return -1;
      }
    }

  FD_ZERO( &rfds );
  FD_SET( sock, &rfds );

  if( select( sock+1, &rfds, NULL, NULL, NULL ) < 0 )
    {
      if (errno != EINTR)
	fprintf(stderr, "select: %s", strerror(errno));

      return -1;
    }

  iov.iov_len = MSG_SIZE_RECV;
  iov.iov_base = (caddr_t) msg;

  memset(&mhdr, 0, sizeof(mhdr));
  mhdr.msg_name = (caddr_t)addr;
  mhdr.msg_namelen = sizeof(*addr);
  mhdr.msg_iov = &iov;
  mhdr.msg_iovlen = 1;
  mhdr.msg_control = (void *)chdr;
  mhdr.msg_controllen = chdrlen;

  len = recvmsg(sock, &mhdr, 0);

  if (len < 0)
    {
      if (errno != EINTR)
	fprintf(stderr, "recvmsg: %s", strerror(errno));

      return len;
    }

  *hoplimit = 255;

  for (cmsg = CMSG_FIRSTHDR(&mhdr); cmsg != NULL; cmsg = CMSG_NXTHDR(&mhdr, cmsg))
    {
      if (cmsg->cmsg_level != IPPROTO_IPV6)
	continue;

      switch(cmsg->cmsg_type)
	{
#ifdef IPV6_HOPLIMIT
	case IPV6_HOPLIMIT:
	  if ((cmsg->cmsg_len == CMSG_LEN(sizeof(int))) &&
	      (*(int *)CMSG_DATA(cmsg) >= 0) &&
	      (*(int *)CMSG_DATA(cmsg) < 256))
	    {
	      *hoplimit = *(int *)CMSG_DATA(cmsg);
	    }
	  else
	    {
	      fprintf(stderr, "received a bogus IPV6_HOPLIMIT from the kernel! len=%d, data=%d",
		   cmsg->cmsg_len, *(int *)CMSG_DATA(cmsg));
	      return (-1);
	    }
	  break;
#endif /* IPV6_HOPLIMIT */
	case IPV6_PKTINFO:
	  if ((cmsg->cmsg_len == CMSG_LEN(sizeof(struct in6_pktinfo))) &&
	      ((struct in6_pktinfo *)CMSG_DATA(cmsg))->ipi6_ifindex)
	    {
	      *pkt_info = (struct in6_pktinfo *)CMSG_DATA(cmsg);
	    }
	  else
	    {
	      fprintf(stderr, "received a bogus IPV6_PKTINFO from the kernel! len=%d, index=%d",
		   cmsg->cmsg_len, ((struct in6_pktinfo *)CMSG_DATA(cmsg))->ipi6_ifindex);
	      return (-1);
	    }
	  break;
	 case RPL_CODE_DAO:
	  if ((cmsg->cmsg_len == CMSG_LEN(sizeof(struct in6_pktinfo))) &&
	      ((struct in6_pktinfo *)CMSG_DATA(cmsg))->ipi6_ifindex)
	    {
	      *pkt_info = (struct in6_pktinfo *)CMSG_DATA(cmsg);
	    }
	  else
	    {
	      fprintf(stderr, "received a bogus RPL_CODE_DAO ! len=%d, index=%d",
		   cmsg->cmsg_len, ((struct in6_pktinfo *)CMSG_DATA(cmsg))->ipi6_ifindex);
	      return (-1);
	    }
	  break;

	}
    }

  fprintf(stdout, "recvmsg len=%d", len);

  return len;
}

static void
process_dao(unsigned char *msg, int len, struct sockaddr_in6 *addr)
{

}

void
process(unsigned char *msg, int len,
	struct sockaddr_in6 *addr, struct in6_pktinfo *pkt_info, int hoplimit)
{
	struct icmp6_hdr *icmph;
	char addr_str[INET6_ADDRSTRLEN];

	print_addr(&addr->sin6_addr, addr_str);

	if ( ! pkt_info )
	{
		fprintf(stderr, "received packet with no pkt_info from %s!", addr_str );
		return;
	}

	/*
	 * can this happen?
	 */

	if (len < sizeof(struct icmp6_hdr))
	{
		fprintf(stderr, "received icmpv6 packet with invalid length (%d) from %s",
			len, addr_str);
		return;
	}

	icmph = (struct icmp6_hdr *) msg;

	if (icmph->icmp6_type != ICMP6_RPL)
	{
		/*
		 *	We just want to listen to DAOs
		 */

		fprintf(stderr, "icmpv6 filter failed");
		return;
	}

	if (icmph->icmp6_type == ND_ROUTER_ADVERT)
	{
		if (len < sizeof(struct nd_router_advert)) {
			fprintf(stderr, "received icmpv6 RA packet with invalid length (%d) from %s",
				len, addr_str);
			return;
		}

		if (!IN6_IS_ADDR_LINKLOCAL(&addr->sin6_addr)) {
			fprintf(stderr, "received icmpv6 RA packet with non-linklocal source address from %s", addr_str);
			return;
		}
	}

	if (icmph->icmp6_type == ND_ROUTER_SOLICIT)
	{
		if (len < sizeof(struct nd_router_solicit)) {
			fprintf(stderr, "received icmpv6 RS packet with invalid length (%d) from %s",
				len, addr_str);
			return;
		}
	}

	if (icmph->icmp6_code != 0)
	{
		fprintf(stderr, "received icmpv6 RS/RA packet with invalid code (%d) from %s",
			icmph->icmp6_code, addr_str);
		return;
	}

	fprintf(stderr, "if_index %u", pkt_info->ipi6_ifindex);

	if (hoplimit != 255)
	{
		print_addr(&addr->sin6_addr, addr_str);
		fprintf(stderr, "received RS or RA with invalid hoplimit %d from %s",
			hoplimit, addr_str);
		return;
	}

//fprintf(stderr, dlog(LOG_DEBUG, 4, "found Interface: %s", iface->Name);

	if (icmph->icmp6_type == ICMP6_RPL)
	{
		fprintf(stdout, "received DAO from %s", addr_str);
		process_dao(msg, len, addr);
	}
	else
	{
		fprintf(stderr, "unknown ICMPv6 type %i\n", icmph->icmp6_type);
	}
}


