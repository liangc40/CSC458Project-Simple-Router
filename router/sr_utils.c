#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "sr_protocol.h"
#include "sr_utils.h"


uint16_t cksum (const void *_data, int len) {
  const uint8_t *data = _data;
  uint32_t sum;

  for (sum = 0;len >= 2; data += 2, len -= 2)
    sum += data[0] << 8 | data[1];
  if (len > 0)
    sum += data[0] << 8;
  while (sum > 0xffff)
    sum = (sum >> 16) + (sum & 0xffff);
  sum = htons (~sum);
  return sum ? sum : 0xffff;
}

uint16_t check_ip_checksum(sr_ip_hdr_t *data) {
  printf("Function: check_ip_checksum\n");
  uint16_t org_ip_sum = data->ip_sum;
  printf("check_ip_checksum: orgin check sum: %d\n", org_ip_sum);

  data->ip_sum = 0;
  uint16_t received_ip_checksum = cksum(data, (data->ip_hl * 4));
  printf("check_ip_checksum: received check sum: %d\n", received_ip_checksum);
  if (org_ip_sum != received_ip_checksum) {
    data->ip_sum = org_ip_sum;
    return 1;
  } else {
    data->ip_sum = org_ip_sum;
    return 0;
  }
}

uint16_t check_icmp_checksum(uint8_t *packet) {
  printf("Function: check_icmp_checksum\n");
  sr_ip_hdr_t *ip_header = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
  sr_icmp_hdr_t *icmp_header = (sr_icmp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
  uint16_t org_icmp_sum = icmp_header->icmp_sum;
  printf("check_icmp_checksum: orgin check sum: %d\n", org_icmp_sum);

  icmp_header->icmp_sum = 0;
  uint16_t received_icmp_checksum = cksum(icmp_header, ntohs(ip_header->ip_len) - (ip_header->ip_hl * 4));
  printf("check_icmp_checksum: received check sum: %d\n", received_icmp_checksum);
  if (org_icmp_sum != received_icmp_checksum) {
    icmp_header->icmp_sum = org_icmp_sum;
    return 1;
  } else {
    icmp_header->icmp_sum = org_icmp_sum;
    return 0;
  }
}


uint16_t ethertype(uint8_t *buf) {
  sr_ethernet_hdr_t *ehdr = (sr_ethernet_hdr_t *)buf;
  return ntohs(ehdr->ether_type);
}

uint8_t ip_protocol(uint8_t *buf) {
  sr_ip_hdr_t *iphdr = (sr_ip_hdr_t *)(buf);
  return iphdr->ip_p;
}


/* Prints out formatted Ethernet address, e.g. 00:11:22:33:44:55 */
void print_addr_eth(uint8_t *addr) {
  int pos = 0;
  uint8_t cur;
  for (; pos < ETHER_ADDR_LEN; pos++) {
    cur = addr[pos];
    if (pos > 0)
      fprintf(stderr, ":");
    fprintf(stderr, "%02X", cur);
  }
  fprintf(stderr, "\n");
}

/* Prints out IP address as a string from in_addr */
void print_addr_ip(struct in_addr address) {
  char buf[INET_ADDRSTRLEN];
  if (inet_ntop(AF_INET, &address, buf, 100) == NULL)
    fprintf(stderr,"inet_ntop error on address conversion\n");
  else
    fprintf(stderr, "%s\n", buf);
}

/* Prints out IP address from integer value */
void print_addr_ip_int(uint32_t ip) {
  uint32_t curOctet = ip >> 24;
  fprintf(stderr, "%d.", curOctet);
  curOctet = (ip << 8) >> 24;
  fprintf(stderr, "%d.", curOctet);
  curOctet = (ip << 16) >> 24;
  fprintf(stderr, "%d.", curOctet);
  curOctet = (ip << 24) >> 24;
  fprintf(stderr, "%d\n", curOctet);
}


/* Prints out fields in Ethernet header. */
void print_hdr_eth(uint8_t *buf) {
  sr_ethernet_hdr_t *ehdr = (sr_ethernet_hdr_t *)buf;
  fprintf(stderr, "ETHERNET header:\n");
  fprintf(stderr, "\tdestination: ");
  print_addr_eth(ehdr->ether_dhost);
  fprintf(stderr, "\tsource: ");
  print_addr_eth(ehdr->ether_shost);
  fprintf(stderr, "\ttype: %d\n", ntohs(ehdr->ether_type));
}

/* Prints out fields in IP header. */
void print_hdr_ip(uint8_t *buf) {
  sr_ip_hdr_t *iphdr = (sr_ip_hdr_t *)(buf);
  fprintf(stderr, "IP header:\n");
  fprintf(stderr, "\tversion: %d\n", iphdr->ip_v);
  fprintf(stderr, "\theader length: %d\n", iphdr->ip_hl);
  fprintf(stderr, "\ttype of service: %d\n", iphdr->ip_tos);
  fprintf(stderr, "\tlength: %d\n", ntohs(iphdr->ip_len));
  fprintf(stderr, "\tid: %d\n", ntohs(iphdr->ip_id));

  if (ntohs(iphdr->ip_off) & IP_DF)
    fprintf(stderr, "\tfragment flag: DF\n");
  else if (ntohs(iphdr->ip_off) & IP_MF)
    fprintf(stderr, "\tfragment flag: MF\n");
  else if (ntohs(iphdr->ip_off) & IP_RF)
    fprintf(stderr, "\tfragment flag: R\n");

  fprintf(stderr, "\tfragment offset: %d\n", ntohs(iphdr->ip_off) & IP_OFFMASK);
  fprintf(stderr, "\tTTL: %d\n", iphdr->ip_ttl);
  fprintf(stderr, "\tprotocol: %d\n", iphdr->ip_p);

  /*Keep checksum in NBO*/
  fprintf(stderr, "\tchecksum: %d\n", iphdr->ip_sum);

  fprintf(stderr, "\tsource: ");
  print_addr_ip_int(ntohl(iphdr->ip_src));

  fprintf(stderr, "\tdestination: ");
  print_addr_ip_int(ntohl(iphdr->ip_dst));
}

/* Prints out ICMP header fields */
void print_hdr_icmp(uint8_t *buf) {
  sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t *)(buf);
  fprintf(stderr, "ICMP header:\n");
  fprintf(stderr, "\ttype: %d\n", icmp_hdr->icmp_type);
  fprintf(stderr, "\tcode: %d\n", icmp_hdr->icmp_code);
  /* Keep checksum in NBO */
  fprintf(stderr, "\tchecksum: %d\n", icmp_hdr->icmp_sum);
}


/* Prints out fields in ARP header */
void print_hdr_arp(uint8_t *buf) {
  sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *)(buf);
  fprintf(stderr, "ARP header\n");
  fprintf(stderr, "\thardware type: %d\n", ntohs(arp_hdr->ar_hrd));
  fprintf(stderr, "\tprotocol type: %d\n", ntohs(arp_hdr->ar_pro));
  fprintf(stderr, "\thardware address length: %d\n", arp_hdr->ar_hln);
  fprintf(stderr, "\tprotocol address length: %d\n", arp_hdr->ar_pln);
  fprintf(stderr, "\topcode: %d\n", ntohs(arp_hdr->ar_op));

  fprintf(stderr, "\tsender hardware address: ");
  print_addr_eth(arp_hdr->ar_sha);
  fprintf(stderr, "\tsender ip address: ");
  print_addr_ip_int(ntohl(arp_hdr->ar_sip));

  fprintf(stderr, "\ttarget hardware address: ");
  print_addr_eth(arp_hdr->ar_tha);
  fprintf(stderr, "\ttarget ip address: ");
  print_addr_ip_int(ntohl(arp_hdr->ar_tip));
}

/* Prints out all possible headers, starting from Ethernet */
void print_hdrs(uint8_t *buf, uint32_t length) {

  /* Ethernet */
  int minlength = sizeof(sr_ethernet_hdr_t);
  if (length < minlength) {
    fprintf(stderr, "Failed to print ETHERNET header, insufficient length\n");
    return;
  }

  uint16_t ethtype = ethertype(buf);
  print_hdr_eth(buf);

  if (ethtype == ethertype_ip) { /* IP */
    minlength += sizeof(sr_ip_hdr_t);
    if (length < minlength) {
      fprintf(stderr, "Failed to print IP header, insufficient length\n");
      return;
    }

    print_hdr_ip(buf + sizeof(sr_ethernet_hdr_t));
    uint8_t ip_proto = ip_protocol(buf + sizeof(sr_ethernet_hdr_t));

    if (ip_proto == ip_protocol_icmp) { /* ICMP */
      minlength += sizeof(sr_icmp_hdr_t);
      if (length < minlength)
        fprintf(stderr, "Failed to print ICMP header, insufficient length\n");
      else
        print_hdr_icmp(buf + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
    }
  }
  else if (ethtype == ethertype_arp) { /* ARP */
    minlength += sizeof(sr_arp_hdr_t);
    if (length < minlength)
      fprintf(stderr, "Failed to print ARP header, insufficient length\n");
    else
      print_hdr_arp(buf + sizeof(sr_ethernet_hdr_t));
  }
  else {
    fprintf(stderr, "Unrecognized Ethernet Type: %d\n", ethtype);
  }
}

/*
 * Send an ICMP message to sending host when an echo request is received.
 *
 * Echo reply: type 0
 *
 */
 void sr_send_icmp_message(struct sr_instance* sr, uint8_t* packet, unsigned int len) {
   /*
    * ICMP message: MAC header | IP header | ICMP header | Data
    * ICMP header: type | code | checksum
    *
    * Send original packet back to the sender.
    */
    printf("sr_send_icmp_message called!! \n");

    /* Modify IP header */
    sr_ip_hdr_t *ip_header = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));

    /* Get ip address of sender wich is the echo requestor, and assign as
     * destination address.
     * And source address will be specific-destination address of
     * the corresponding ICMP Echo Request.
     */
    uint32_t requestor_ip = ip_header->ip_src;
    ip_header->ip_src = ip_header->ip_dst;
    ip_header->ip_dst = requestor_ip;

    /* Create ICMP header */
    sr_icmp_hdr_t *icmp_header = (sr_icmp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
    icmp_header->icmp_type = icmp_type_echo_reply;
    icmp_header->icmp_code = icmp_type_echo_reply;

    /* clear checksum field to 0 */
    icmp_header->icmp_sum = 0;
    /* compute checksum for icmp header (starting with the ICMP Type field) */
    /* ip header length: (ip_header->ip_hl * 4) */
    icmp_header->icmp_sum = cksum(icmp_header, ntohs(ip_header->ip_len) - (ip_header->ip_hl * 4));

    struct sr_rt *rt_entry = get_longest_prefix_match(sr, requestor_ip);
    /* exit interface */
    struct sr_if *interface = sr_get_interface(sr, rt_entry->interface);
    /* Send packet */
    if (!interface) {
      printf("sr_send_icmp_msg: no interface ????\n");
      return;
    }
    printf("send icmp echo back\n");

    /* send_packet(sr, packet, len, interface, requestor_ip); */
    send_packet(sr, packet, len, interface, rt_entry->gw.s_addr);
}


/*
 * Send an ICMP message to sending host when the destination is unreachable or
 * in the case of timeout.
 *
 * Destination net unreachable: type 3 code 0
 * Destination host unreachable: type 3 code 1
 * Destination port unreachable: type 3 code 3
 * Time exceeded: type 11 code 0
 *
 */
 void sr_send_t3_icmp_msg(struct sr_instance* sr, uint8_t* packet,
   unsigned int len, uint8_t icmp_case) {
    /* Create a new packet for icmp message */
    printf("sr_send_t3_icmp_msg called!! \n");

    /* compute the length of the packet as sum of three headers */
    unsigned int length = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);

    /* Create new ip packet */
    uint8_t *icmp_packet = (uint8_t *)malloc(length);
    /* init all space to 0 */
    memset(icmp_packet, 0, length);

    sr_ethernet_hdr_t *eth_header = (sr_ethernet_hdr_t *)icmp_packet;
    eth_header->ether_type = htons(ethertype_ip);

    /* Create IP header */
    sr_ip_hdr_t *ip_header = (sr_ip_hdr_t *)(icmp_packet + sizeof(sr_ethernet_hdr_t));
    sr_ip_hdr_t *org_ip_header = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
    uint32_t sender_ip = org_ip_header->ip_src;

    struct sr_rt *rt_entry = get_longest_prefix_match(sr, org_ip_header->ip_src);
    /* exit interface */
    struct sr_if *interface = sr_get_interface(sr, rt_entry->interface);
    if (!interface) {
      printf("sr_send_t3_icmp_msg: no interface ????\n");
      return;
    }

    ip_header->ip_v = 4;
    ip_header->ip_hl = sizeof(sr_ip_hdr_t) / 4;
    ip_header->ip_tos = org_ip_header->ip_tos;
    ip_header->ip_len = htons(length - sizeof(sr_ethernet_hdr_t)); /* length of the datagram */
    ip_header->ip_id = htons(0);
    ip_header->ip_off = htons(IP_DF);
    ip_header->ip_ttl = INIT_TTL;
    ip_header->ip_p = ip_protocol_icmp;
    /* if is port unreachable, source ip is the destination ip of origin packet
       else the source ip address is the outgoing interface address. */
    if (icmp_case == unreachable_port) {
      ip_header->ip_src = org_ip_header->ip_dst;
    } else {
      ip_header->ip_src = interface->ip;
    }
    /* ip destination address is sender */
    ip_header->ip_dst = sender_ip;
    /* compute checksum for ip header */
    ip_header->ip_sum = 0;
    ip_header->ip_sum = cksum(ip_header, sizeof(sr_ip_hdr_t));

    /* Create ICMP header */
    sr_icmp_t3_hdr_t *icmp_header = (sr_icmp_t3_hdr_t *)(icmp_packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

    /* Find correspond icmp type and code */
    switch (icmp_case) {
      case unreachable_net: {
        printf("case unreachable_net\n");
        icmp_header->icmp_type = icmp_type_unreachable;
        icmp_header->icmp_code = icmp_code_unreachable_net;
        break;
      }
      case unreachable_host: {
        printf("case unreachable_host\n");
        icmp_header->icmp_type = icmp_type_unreachable;
        icmp_header->icmp_code = icmp_code_unreachable_host;
        break;
      }
      case unreachable_port: {
        printf("case unreachable_port\n");
        icmp_header->icmp_type = icmp_type_unreachable;
        icmp_header->icmp_code = icmp_code_unreachable_port;
        break;
      }
      case timeout: {
        printf("case timeout\n");
        icmp_header->icmp_type = icmp_type_timeout;
        icmp_header->icmp_code = icmp_code_time_exceeded;
        break;
      }
      default: {
        printf("Unrecognized icmp case (not destination unreachable or time exceeded).\n");
      }
    }

    /* copy data from original datagram */
    memcpy(icmp_header->data, org_ip_header, ICMP_DATA_SIZE);
    /* compute checksum for icmp header */
    icmp_header->icmp_sum = 0;
    icmp_header->icmp_sum = cksum(icmp_header, sizeof(sr_icmp_t3_hdr_t));

    send_packet(sr, icmp_packet, length, interface, rt_entry->gw.s_addr);
    free(icmp_packet);
}
