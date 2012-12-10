
#include <stdio.h>
#include <stdlib.h>

#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <netinet/in.h>
#include <netdb.h>            // struct addrinfo
#include <sys/ioctl.h>        // macro ioctl is defined
#include <bits/ioctls.h>      // defines values for argument "request" of ioctl.
#include <arpa/inet.h>        // inet_pton()
#include <net/if.h>           // struct ifreq

//#include "rpl-root-node.h"

#define IP6_HDRLEN 40         // IPv6 header length
//#define ICMP_HDRLEN 8         // ICMP header length for echo request, excludes data
#define ICMP_HDRLEN 4

extern int sock;
extern char* if_str;
extern char* ip_src_str;

// IP checksum function
unsigned short int
checksum (unsigned short int *addr, int len)
{
  int nleft = len;
  int sum = 0;
  unsigned short int *w = addr;
  unsigned short int answer = 0;

  while (nleft > 1) {
    sum += *w++;
    nleft -= sizeof (unsigned short int);
  }

  if (nleft == 1) {
    *(unsigned char *) (&answer) = *(unsigned char *) w;
    sum += answer;
  }

  sum = (sum >> 16) + (sum & 0xFFFF);
  sum += (sum >> 16);
  answer = ~sum;
  return (answer);
}

void
uip_icmp6_send(struct in6_addr *dest, int type, int code, unsigned char* data, int datalen) {
  char ipbuffer[IP6_HDRLEN];
  char icmpbuffer[ICMP_HDRLEN];

  struct iphdr *iphdr = (struct iphdr *)ipbuffer;
  struct icmp6_hdr *icmphdr = (struct icmp6_hdr *)icmpbuffer;

  unsigned char *outpack, *psdhdr;
  struct msghdr msghdr;
  struct cmsghdr *cmsghdr;

  int status, sd, cmsglen, psdhdrlen;
  struct ifreq ifr;
  struct addrinfo hints, *res;
  struct sockaddr_in6 src, dst;
  socklen_t srclen;

  struct iovec iov[2];
  void *tmp;

  int ip_len;
  int ret;

  fprintf (stdout, "Sending ICMPv6 type %i code %i.\n", type, code);

  psdhdr = (unsigned char *) malloc (IP_MAXPACKET * sizeof (unsigned char));
  if (psdhdr == NULL) {
    fprintf (stderr, "ERROR: Cannot allocate memory for array 'psdhdr'.\n");
    exit (EXIT_FAILURE);
  }
  memset (psdhdr, 0, IP_MAXPACKET * sizeof (unsigned char));

  outpack = (unsigned char *) malloc ((IP_MAXPACKET - IP6_HDRLEN - ICMP_HDRLEN) * sizeof (unsigned char));
  if (outpack == NULL) {
    fprintf (stderr, "ERROR: Cannot allocate memory for array 'outpack'.\n");
    exit (EXIT_FAILURE);
  }
  memset (outpack, 0, (IP_MAXPACKET - IP6_HDRLEN - ICMP_HDRLEN) * sizeof (unsigned char));

  // Use ioctl() to lookup interface.
  memset (&ifr, 0, sizeof (ifr));
  snprintf (ifr.ifr_name, sizeof (ifr.ifr_name), "%s", if_str);
  if (ioctl (sock, SIOCGIFINDEX, &ifr) < 0) {
    fprintf(stderr, "ioctl() failed to find interface ");
    return;
  }
  //close (sd);
  printf ("Index for interface %s is %i\n", if_str, ifr.ifr_ifindex);

  //TODO: figure out source ipv6 addr:
  // RTM_GETADDR, ifa_family AF_INET6, ifa_index ifr.ifr_ifindex
  //fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);

  // Fill out hints for getaddrinfo().
  memset (&hints, 0, sizeof (struct addrinfo));
  hints.ai_family = AF_INET6;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = hints.ai_flags | AI_CANONNAME;

  // Resolve source using getaddrinfo().
  if ((status = getaddrinfo (ip_src_str, NULL, &hints, &res)) != 0) {
    fprintf (stderr, "getaddrinfo() failed: %s\n", gai_strerror (status));
    return;
  }
  memcpy (&src, res->ai_addr, res->ai_addrlen);
  srclen = res->ai_addrlen;
  memcpy (psdhdr, src.sin6_addr.s6_addr, 16);  // Copy to checksum pseudo-header
  freeaddrinfo (res);

  // Resolve target using getaddrinfo().
  if ((status = getaddrinfo ("ff02::1a", NULL, &hints, &res)) != 0) { //TODO
    fprintf (stderr, "getaddrinfo() failed: %s\n", gai_strerror (status));
    return;
  }
  memcpy (&dst, res->ai_addr, res->ai_addrlen);
  memcpy (psdhdr + 16, dst.sin6_addr.s6_addr, 16);  // Copy to checksum pseudo-header
  freeaddrinfo (res);

  // Define first part of buffer outpack to be an ICMPV6 struct.
  icmphdr = (struct icmp6_hdr *) outpack;
  memset (icmphdr, 0, ICMP_HDRLEN);

  // Populate icmphdr portion of buffer outpack.
  icmphdr->icmp6_type = type;
  icmphdr->icmp6_code =code;
  icmphdr->icmp6_cksum = 0;
  //icmphdr->icmp6_id = htons (5);
  //icmphdr->icmp6_seq = htons (300);

  // Append ICMP data.
  memcpy (outpack + ICMP_HDRLEN, data, datalen);

  // Need a pseudo-header for checksum calculation. Define length. (RFC 2460)
  // Length = source IP (16 bytes) + destination IP (16 bytes)
  //        + upper layer packet length (4 bytes) + zero (3 bytes)
  //        + next header (1 byte)
  psdhdrlen = 16 + 16 + 4 + 3 + 1 + ICMP_HDRLEN + datalen;

  // Compose the msghdr structure.
  memset (&msghdr, 0, sizeof (msghdr));
  msghdr.msg_name = &dst;             // pointer to socket address structure
  msghdr.msg_namelen = sizeof (dst);  // size of socket address structure

  memset (&iov, 0, sizeof (iov));
  iov[0].iov_base = (unsigned char *) outpack;
  iov[0].iov_len = ICMP_HDRLEN + datalen;
  msghdr.msg_iov = iov;   // scatter/gather array
  msghdr.msg_iovlen = 1;  // number of elements in scatter/gather array

  // Tell msghdr we're adding cmsghdr data to change hop limit.
  // Allocate some memory for our cmsghdr data.
  cmsglen = CMSG_SPACE (sizeof (int));
  tmp = (unsigned char *) malloc (cmsglen * sizeof (unsigned char));
  if (tmp != NULL) {
    msghdr.msg_control = tmp;}
  else {
    fprintf (stderr, "ERROR: Cannot allocate memory for array 'msghdr.msg_control'.\n");
    exit (EXIT_FAILURE);
  }
  memset (msghdr.msg_control, 0, cmsglen);
  msghdr.msg_controllen = cmsglen;

  fprintf (stderr, "psdhdrlen.\n");

  cmsghdr = CMSG_FIRSTHDR (&msghdr);
  cmsghdr->cmsg_level = IPPROTO_IPV6;
  cmsghdr->cmsg_type = IPV6_HOPLIMIT;  // We want to change hop limit
  cmsghdr->cmsg_len = CMSG_LEN (sizeof (int));
  *((int *) CMSG_DATA (cmsghdr)) = 0xff;

  // Compute ICMPv6 checksum (RFC 2460).
  // psdhdr[0 to 15] = source IPv6 address, set earlier.
  // psdhdr[16 to 31] = destination IPv6 address, set earlier.
  psdhdr[32] = 0;  // Length should not be greater than 65535 (i.e., 2 bytes)
  psdhdr[33] = 0;  // Length should not be greater than 65535 (i.e., 2 bytes)
  psdhdr[34] = (ICMP_HDRLEN + datalen)  / 256;  // Upper layer packet length
  psdhdr[35] = (ICMP_HDRLEN + datalen)  % 256;  // Upper layer packet length
  psdhdr[36] = 0;  // Must be zero
  psdhdr[37] = 0;  // Must be zero
  psdhdr[38] = 0;  // Must be zero
  psdhdr[39] = IPPROTO_ICMPV6;

  memcpy (psdhdr + 40, outpack, ICMP_HDRLEN + datalen);
  icmphdr->icmp6_cksum = checksum ((unsigned short int *) psdhdr, psdhdrlen);

  printf ("Checksum: %x\n", ntohs (icmphdr->icmp6_cksum));
  //ip_len = IP6_HDRLEN + ICMP_HDRLEN + payload_len;

  // Bind the socket descriptor to the source address.
  if (bind (sock, (struct sockaddr *) &src, srclen) != 0) {
    fprintf (stderr, "Failed to bind the socket descriptor to the source address.\n");
    return;
  }

  // Bind socket to interface index.
  if (setsockopt (sock, SOL_SOCKET, SO_BINDTODEVICE, &ifr, sizeof (ifr)) < 0) {
    fprintf(stderr, "setsockopt() failed to bind to interface\n");
    return;
  }

  // Send packet.
  ret = sendmsg (sock, &msghdr, 0);
  if (ret < 0) {
    fprintf(stderr, "sendmsg() failed %i %i '%s'\n", ret, status, gai_strerror (status));
    return;
  } else {
    fprintf(stdout, "sendmsg() success\n" );
  }
  //close (sd);

}
