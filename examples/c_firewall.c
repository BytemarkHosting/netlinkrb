/* Adapted from http://people.redhat.com/nhorman/papers/netlink.pdf */

#include <sys/types.h>
#include <sys/socket.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netlink.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4/ip_queue.h>

/*
 * Warning: all messages must be padded to the larger of ipq_verdict_msg
 * and ipq_mode_msg (struct ipq_peer_msg), since the kernel enforces this:
 *
 *        // net/ipv4/netfilter/ip_queue.c
 *        // function ipq_receive_peer
 *        if (len < sizeof(*pmsg))
 *                        return -EINVAL;
 */

int main(void) {
  int netlink_socket;
  int seq=0;

  struct sockaddr_nl addr;
  socklen_t addrlen;
  struct nlmsghdr *nl_header = NULL;
  struct ipq_mode_msg *mode_data = NULL;
  struct ipq_packet_msg *pkt_data = NULL;
  struct ipq_verdict_msg *ver_data = NULL;
  struct nlmsgerr *nl_error = NULL;

  unsigned char buf1[128];
  unsigned char buf2[128];

  /*create the socket*/
  netlink_socket = socket(AF_NETLINK,SOCK_RAW,NETLINK_FIREWALL);

  /*set up the socket address structure*/
  memset(&addr,0,sizeof(struct sockaddr_nl));
  addr.nl_family=AF_NETLINK;
  addr.nl_pid=0;/*packets are destined for the kernel*/
  addr.nl_groups=0;/*we don’t need any multicast groups*/

  /*
  *we need to send a mode message first, so fill
  *out the nlmsghdr structure as such
  */

  nl_header=(struct nlmsghdr *)buf1;
  nl_header->nlmsg_type=IPQM_MODE;
  nl_header->nlmsg_len=NLMSG_LENGTH(sizeof(struct ipq_peer_msg));
  nl_header->nlmsg_flags=(NLM_F_REQUEST);/*this is a request, don’t ask for an answer*/
  nl_header->nlmsg_pid=getpid();
  nl_header->nlmsg_seq=seq++;/*arbitrary unique value to allow response correlation*/

  mode_data=NLMSG_DATA(nl_header);
  mode_data->value=IPQ_COPY_META;
  mode_data->range=0;/*when mode is PACKET, 0 here means copy whole packet*/

  if(sendto(netlink_socket,(void *)nl_header,nl_header->nlmsg_len,0,
  (struct sockaddr *)&addr,sizeof(struct sockaddr_nl)) < 0) {
    perror("unable to send mode message");
    exit(0);
  }

  /*
  *we're ready to filter packets
  */

  for(;;) {
    addrlen = sizeof(addr);
    if(recvfrom(netlink_socket,buf1,NLMSG_LENGTH(sizeof(struct ipq_packet_msg)),
    0,(struct sockaddr*)&addr,&addrlen) < 0) {
      perror("Unable to receive packet message");
      exit(0);
    }

    /*
    *once we have the packet message, lets extract the header and ancilliary data
    */

    nl_header=(struct nlmsghdr *)buf1;
    switch (nl_header->nlmsg_type) {
      case IPQM_PACKET:
        break;
      case NLMSG_ERROR:
        nl_error = NLMSG_DATA(nl_header);
        fprintf(stderr, "Received error %d\n", nl_error->error);
        exit(1);
      default:
        fprintf(stderr, "Received unexpected packet type %d\n", nl_header->nlmsg_type);
        exit(2);
    }

    pkt_data=NLMSG_DATA(nl_header);

    /*for the example just forward all packets*/

    nl_header=(struct nlmsghdr *)buf2;
    nl_header->nlmsg_type=IPQM_VERDICT;
    nl_header->nlmsg_len=NLMSG_LENGTH(sizeof(struct ipq_verdict_msg));
    nl_header->nlmsg_flags=(NLM_F_REQUEST);/*this is a request, don’t ask for an answer*/
    nl_header->nlmsg_pid=getpid();
    nl_header->nlmsg_seq=seq++;/*arbitrary unique value to allow response correlation*/
    ver_data=(struct ipq_verdict_msg *)NLMSG_DATA(nl_header);
    ver_data->value=NF_ACCEPT;
    ver_data->id=pkt_data->packet_id;
    if(sendto(netlink_socket,(void *)nl_header,nl_header->nlmsg_len,0,
    (struct sockaddr *)&addr,sizeof(struct sockaddr_nl)) < 0) {
      perror("unable to send mode message");
      exit(0);
    }
  }
}
