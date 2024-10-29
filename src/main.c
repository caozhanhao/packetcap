#include <stdio.h>
#include <stdlib.h>

#include <netinet/if_ether.h>
#include <net/ethernet.h>

#include <pcap/pcap.h>

#include "sniff/sniff.h"

void print_ip_packet(uint32_t protocol, uint32_t size_ip,
                     const struct pcap_pkthdr* pkthdr, const uint8_t* packet)
{
  switch (protocol)
  {
    case IPPROTO_TCP:
    {
      const struct TCPHeader* tcp = (struct TCPHeader*) packet;
      uint32_t size_tcp = TH_OFF(tcp) * 4;
      if (size_tcp < 20)
      {
        printf("Error: Invalid TCP header length: %u bytes\n", size_tcp);
        return;
      }
      uint32_t size_headers = size_ip + size_tcp + SIZE_ETHERNET;
      printf("TCP header length in bytes: %u\n", size_tcp);
      printf("Size of all headers combined: %d bytes\n", size_headers);
      printf("Payload size: %u bytes\n", pkthdr->len - size_headers);
    }
    break;
    case IPPROTO_UDP:
    {
      const struct UDPHeader* udp = (struct UDPHeader*) packet;
      printf("Source Port: %u\n", udp->uh_sport);
      printf("Destination Port: %u\n", udp->uh_dport);
      uint32_t size_headers = size_ip + SIZE_UDP + SIZE_ETHERNET;
      printf("UDP header length in bytes: %u\n", SIZE_UDP);
      printf("Size of all headers combined: %d bytes\n", size_headers);
      printf("Payload size: %u bytes\n", pkthdr->len - size_headers);
    }
    break;
    case IPPROTO_ICMP:
    {
      const struct ICMPHeader* icmp = (struct ICMPHeader*) packet;
      uint32_t size_headers = size_ip + SIZE_ICMP + SIZE_ETHERNET;
      printf("ICMP Type: %s\n", get_icmp_name(icmp->icmp_type));
      printf("ICMP Code: %u\n", icmp->icmp_code);
      printf("ICMP header length in bytes: %u\n", SIZE_ICMP);
      printf("Size of all headers combined: %d bytes\n", size_headers);
      printf("Payload size: %u bytes\n", pkthdr->len - size_headers);
    }
    break;
    default:
      break;
  }
}

void print_packet(uint8_t* user, const struct pcap_pkthdr* pkthdr, const uint8_t* packet)
{
  printf("<----------- New Packet Arrived! ----------->\n");
  printf("Total packet available: %u bytes\n", pkthdr->caplen);
  printf("Expected package size: %d bytes\n", pkthdr->len);

  const struct ETHeader* ethernet = (struct ETHeader*) packet;
  ushort protocol = ntohs(ethernet->ether_type);
  printf("Protocol: %s\n", get_protocol_name(protocol));

  switch (protocol)
  {
    case ETHERTYPE_IP:
    {
      const struct IPHeader* ip = (struct IPHeader*) (packet + SIZE_ETHERNET);
      uint32_t size_ip = IP_HL(ip) * 4;
      if (size_ip < 20)
      {
        printf("Error: Invalid IP header length: %u bytes\n", size_ip);
        return;
      }
      char ip_src_str[INET_ADDRSTRLEN];
      char ip_dst_str[INET_ADDRSTRLEN];
      inet_ntop(AF_INET, &ip->ip_src, ip_src_str, INET_ADDRSTRLEN);
      inet_ntop(AF_INET, &ip->ip_dst, ip_dst_str, INET_ADDRSTRLEN);

      printf("IP header length (IHL) in bytes: %u\n", size_ip);
      printf("Source Address: %s\n", ip_src_str);
      printf("Destination Address: %s\n", ip_dst_str);
      printf("IP protocol: %s\n", get_ip_protocol_name(ip->ip_p));

      print_ip_packet(ip->ip_p, size_ip, pkthdr, packet + SIZE_ETHERNET + size_ip);
    }
    break;
    case ETHERTYPE_IPV6:
      const struct IP6Header* ip6 = (struct IP6Header*) (packet + SIZE_ETHERNET);
      char ip6_src_str[INET6_ADDRSTRLEN];
      char ip6_dst_str[INET6_ADDRSTRLEN];
      inet_ntop(AF_INET6, &ip6->ip6_src, ip6_src_str, INET6_ADDRSTRLEN);
      inet_ntop(AF_INET6, &ip6->ip6_dst, ip6_dst_str, INET6_ADDRSTRLEN);

      printf("IPV6 header length (IHL) in bytes: %u\n", SIZE_IP6);
      printf("Source Address: %s\n", ip6_src_str);
      printf("Destination Address: %s\n", ip6_dst_str);

      printf("IPV6 protocol: %s\n", get_ip_protocol_name(ip6->ip6_nxt));

      print_ip_packet(ip6->ip6_nxt, SIZE_IP6, pkthdr,
                      packet + SIZE_ETHERNET + SIZE_IP6);
      break;
    default:
      break;
  }
  fflush(stdout);
}

int main()
{
  char errbuf[PCAP_ERRBUF_SIZE] = {0};
  char* dev = pcap_lookupdev(errbuf);
  if (dev == NULL)
  {
    fprintf(stderr, "pcap_lookupdev() failed:  %s\n", errbuf);
    exit(-1);
  }
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 0, errbuf);
  if (handle == NULL)
  {
    fprintf(stderr, "pcap_open_live() failed:  %s\n", errbuf);
    exit(-1);
  }

  printf("Packet sniffing over '%s' started.\n", dev);
  while (1)
  {
    pcap_loop(handle, -1, print_packet, NULL);
  }
  return 0;
}
