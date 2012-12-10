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
#include <poll.h>
#include <errno.h>

#include "rpl.h"
#include "config.h"

#include "rpl-root-node.h"
#include "defines.h"

int sock = -1;

static int quit = 0;

//TODO: read from optarg
uint16_t dag_id[] = {0x1111, 0x1100, 0, 0, 0, 0, 0, 0x0011};

void main_loop(void);

void
usage( const char *program, const char *version) {
  const char *p;

  p = strrchr( program, '/' );
  if ( p )
    program = ++p;

  fprintf( stderr, "%s v%s -- a RPL root node implementation derived from Contiki\n"
	   "(c) 2012 Markus Becker <mab@comnets.uni-bremen.de>\n\n"
	   "usage: %s [-i interface] [-s sourceaddress]\n\n"
	   "\t-i interface\tinterface to operate the RPL root node on\n"
	   "\t-s sourceaddress\tsourceaddress to use\n",
	   program, version, program );
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

  sock = open_icmpv6_socket();
  if (sock < 0) {
    fprintf(stderr, "open_icmpv6_socket failed");
    exit(1);
  }

  // start RPL
  fprintf(stdout, "RPL-Border router started on interface %s (%s)\n",
	  if_str, ip_src_str);

  dag = rpl_set_root(RPL_DEFAULT_INSTANCE,(struct in6_addr *)dag_id);
  if(dag != NULL) {
    rpl_set_prefix(dag, &prefix, 64);
    fprintf(stdout, "created a new RPL dag\n");
  }

  main_loop();

  //TODO: more cleanup?
  close(sock);

  return 0;
}

void main_loop(void)
{
  struct pollfd fds[2];

  memset(fds, 0, sizeof(fds));

  fds[0].fd = sock;
  fds[0].events = POLLIN;
  fds[0].revents = 0;

  /*
    #if HAVE_NETLINK
    fds[1].fd = netlink_socket();
    fds[1].events = POLLIN;
    fds[1].revents = 0;
    #else
    fds[1].fd = -1;
    fds[1].events = 0;
    fds[1].revents = 0;
    #endif
  */
  for (;;) {
    //struct Interface *next = NULL;
    //struct Interface *iface;
    int timeout = 50;
    int rc;

    /*
    if (IfaceList) {
      timeout = next_time_msec(IfaceList);
      next = IfaceList;
      for (iface = IfaceList; iface; iface = iface->next) {
	int t;
	t = next_time_msec(iface);
	if (timeout > t) {
	  timeout = t;
	  next = iface;
	}
      }
      }*/

    //dlog(LOG_DEBUG, 5, "polling for %g seconds.", timeout/1000.0);

    rc = poll(fds, sizeof(fds)/sizeof(fds[0]), timeout);

    if (rc > 0) {
      if (fds[0].revents & (POLLERR | POLLHUP | POLLNVAL)) {
	fprintf(stderr, "socket error on fds[0].fd");
      }
      else if (fds[0].revents & POLLIN) {
	int len, hoplimit;
	struct sockaddr_in6 rcv_addr;
	struct in6_pktinfo *pkt_info = NULL;
	unsigned char msg[MSG_SIZE_RECV];

	fprintf(stdout, "incoming ICMPv6 message?!");

	//TODO: handle incoming DAOs

	len = recv_dao(msg, &rcv_addr, &pkt_info, &hoplimit);
	if (len > 0) {
	  process(msg, len, &rcv_addr, pkt_info, hoplimit);
	}
      }
#ifdef HAVE_NETLINK
      if (fds[1].revents & (POLLERR | POLLHUP | POLLNVAL)) {
	flog(LOG_WARNING, "socket error on fds[1].fd");
      }
      else if (fds[1].revents & POLLIN) {
	process_netlink_msg(fds[1].fd);
      }
#endif
    }
    /*else if ( rc == 0 ) {
      fprintf(stderr, "poll handler: %s", strerror(errno));
            if (next)
	      timer_handler(next);
	      }*/
    else if ( rc == -1 ) {
      //fprintf(stderr, "poll returned early: %s", strerror(errno));
    }

    /*
    if (sigterm_received || sigint_received) {
      flog(LOG_WARNING, "Exiting, sigterm or sigint received.\n");
      break;
    }

    if (sighup_received)
      {
	dlog(LOG_INFO, 3, "sig hup received.\n");
	reload_config();
	sighup_received = 0;
      }

    if (sigusr1_received)
      {
	dlog(LOG_INFO, 3, "sig usr1 received.\n");
	reset_prefix_lifetimes();
	sigusr1_received = 0;
      }
    */
  }
}
