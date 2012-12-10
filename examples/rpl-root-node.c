/* librpl -- simple implementation of the Routing Protocol for Low
 *           power and Lossy Networks (derived from Contiki's
 *           implementation)
 *
 * Copyright (C) 2012 Markus Becker <mab@comnets.uni-bremen.de>
 *
 * This file is part of the RPL library librpl. Please see README for
 * terms of use.
 */

#include <stdio.h>
#include <string.h>
#include <unistd.h>
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

#include "rpl.h"
#include "config.h"

#define DEFAULT_IF "lowpan0"
static char* if_str = NULL;

//TODO: read source address from libnl instead of optarg
//      e.g. http://airtower.wordpress.com/2010/07/16/first-steps-with-libnl/
#define DEFAULT_IPV6_SRC "::1"
static char* ip_src_str = NULL;

#define DEBUG 1

#define PKT_LEN 8192

#define IP6_HDRLEN 40         // IPv6 header length
//#define ICMP_HDRLEN 8         // ICMP header length for echo request, excludes data
#define ICMP_HDRLEN 4

//TODO: read from optarg
uint16_t dag_id[] = {0x1111, 0x1100, 0, 0, 0, 0, 0, 0x0011};

static struct in6_addr prefix;

static int quit = 0;

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
usage( const char *program, const char *version) {
  const char *p;

  p = strrchr( program, '/' );
  if ( p )
    program = ++p;

  fprintf( stderr, "%s v%s -- a RPL root node implementation derived from Contiki\n"
	   "(c) 2012 Markus Becker <mab@comnets.uni-bremen.de>\n\n"
	   "usage: %s [-i interface]\n\n"
	   "\t-i interface\tinterface to operate the RPL root node on\n",
	   program, version, program );
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

  // Submit request for a socket descriptor to lookup interface.
  if ((sd = socket (AF_INET6, SOCK_RAW, IPPROTO_IPV6)) < 0) {
    fprintf(stderr, "socket() failed to get socket descriptor for using ioctl() ");
    return;
  }

  // Use ioctl() to lookup interface.
  memset (&ifr, 0, sizeof (ifr));
  snprintf (ifr.ifr_name, sizeof (ifr.ifr_name), "%s", if_str);
  if (ioctl (sd, SIOCGIFINDEX, &ifr) < 0) {
    fprintf(stderr, "ioctl() failed to find interface ");
    return;
  }
  close (sd);
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

//  ip->ip6_vtc = 0x60;
//ip->tcflow = 0;
//  ip->ip6_flow = 0;
//  ip->nxt = IPPROTO_ICMPV6;
//ip->proto = IPPROTO_ICMP6;
//  ip->hlim = 0xff;
//TODO:
//ip->len[0] = (UIP_ICMPH_LEN + payload_len) >> 8;
//ip->len[1] = (UIP_ICMPH_LEN + payload_len) & 0xff;

//memcpy(&UIP_IP_BUF->destipaddr, dest, sizeof(*dest));
//uip_ds6_select_src(&UIP_IP_BUF->srcipaddr, &UIP_IP_BUF->destipaddr);

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

  // Request a socket descriptor sd.
  if ((sd = socket (AF_INET6, SOCK_RAW, IPPROTO_ICMPV6)) < 0) {
    fprintf (stderr, "Failed to get socket descriptor.\n");
    return;
  }

  // Bind the socket descriptor to the source address.
  if (bind (sd, (struct sockaddr *) &src, srclen) != 0) {
    fprintf (stderr, "Failed to bind the socket descriptor to the source address.\n");
    return;
  }

  // Bind socket to interface index.
  if (setsockopt (sd, SOL_SOCKET, SO_BINDTODEVICE, &ifr, sizeof (ifr)) < 0) {
    fprintf(stderr, "setsockopt() failed to bind to interface\n");
    return;
  }

  // Send packet.
  //fprintf(stderr, "sendmsg... %p %x %x %x %x %x %x\n", msghdr,
  //	  msghdr[0], msghdr[1], msghdr[2], msghdr[3], msghdr[4], msghdr[5]);
  ret = sendmsg (sd, &msghdr, 0);
  if (ret < 0) {
    fprintf(stderr, "sendmsg() failed %i %i '%s'\n", ret, status, gai_strerror (status));
    return;
  } else {
    fprintf(stdout, "sendmsg() success\n" );
  }
  close (sd);

}

int
main(int argc, char **argv) {

  int opt;

  rpl_dag_t *dag;

  while ((opt = getopt(argc, argv, "i:s:")) != -1) {
    switch (opt) {
    case 'i':
      if_str = strdup(optarg);
      break;
    case 's':
      ip_src_str = strdup(optarg);
      break;

    default:
      usage( argv[0], PACKAGE_VERSION );
      exit( 1 );
    }
  }

  // handle default values
  if (if_str == NULL) {
    if_str = malloc(sizeof(DEFAULT_IF));
    strcpy(if_str, DEFAULT_IF);
  }
  if (ip_src_str == NULL) {
    ip_src_str = malloc(sizeof(DEFAULT_IPV6_SRC));
    strcpy(ip_src_str, DEFAULT_IPV6_SRC);
  }

  // start RPL
  fprintf(stdout, "RPL-Border router started on interface %s (%s)\n",
	  if_str, ip_src_str);

  dag = rpl_set_root(RPL_DEFAULT_INSTANCE,(struct in6_addr *)dag_id);
  if(dag != NULL) {
    rpl_set_prefix(dag, &prefix, 64);
    fprintf(stdout, "created a new RPL dag\n");
  }

  while ( !quit ) {

  }


  return 0;
}
