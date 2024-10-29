#include "sniff/sniff.h"

inline const char* get_protocol_name(uint16_t protocol)
{
  switch (protocol)
  {
    case ETHERTYPE_PUP:
      return "PUP (Xerox PUP)";
    case ETHERTYPE_SPRITE:
      return "Sprite";
    case ETHERTYPE_IP:
      return "IP";
    case ETHERTYPE_ARP:
      return "ARP (Address resolution)";
    case ETHERTYPE_REVARP:
      return "RARP (Reverse ARP)";
    case ETHERTYPE_AT:
      return "AT (AppleTalk protocol)";
    case ETHERTYPE_AARP:
      return "AARP (AppleTalk ARP)";
    case ETHERTYPE_VLAN:
      return "VLAN (IEEE 802.1Q VLAN)";
    case ETHERTYPE_IPX:
      return "IPX";
    case ETHERTYPE_IPV6:
      return "IPV6";
    case ETHERTYPE_LOOPBACK:
      return "Loopback";
    default:
      break;
  }
  return "Unknown protocol";
}

inline const char* get_ip_protocol_name(uint8_t protocol)
{
  switch (protocol)
  {
    case IPPROTO_ICMP:
      return "ICMP (Internet Control Message Protocol)";
    case IPPROTO_IGMP:
      return "IGMP (Internet Group Management Protocol)";
    case IPPROTO_IPIP:
      return "IPIP tunnels  (older KA9Q tunnels use 94)";
    case IPPROTO_TCP:
      return "TCP (Transmission Control Protocol)";
    case IPPROTO_EGP:
      return "EGP (Exterior Gateway Protocol)";
    case IPPROTO_PUP:
      return "PUP";
    case IPPROTO_UDP:
      return "UDP (User Datagram Protocol)";
    case IPPROTO_IDP:
      return "IDP (XNS IDP protocol)";
    case IPPROTO_TP:
      return "TP (SO Transport Protocol Class 4)";
    case IPPROTO_DCCP:
      return "DCCP (Datagram Congestion Control Protocol)";
    case IPPROTO_IPV6:
      return "IPv6";
    case IPPROTO_RSVP:
      return "RSVP (Reservation Protocol)";
    case IPPROTO_GRE:
      return "GRE (General Routing Encapsulation)";
    case IPPROTO_ESP:
      return "ESP (encapsulating security payload)";
    case IPPROTO_AH:
      return "AH (authentication header)";
    case IPPROTO_MTP:
      return "MTP (Multicast Transport Protocol)";
    case IPPROTO_BEETPH:
      return "BEETPH (IP option pseudo header for BEET)";
    case IPPROTO_ENCAP:
      return "ENCAP (Encapsulation Header)";
    case IPPROTO_PIM:
      return "PIM (Protocol Independent Multicast)";
    case IPPROTO_COMP:
      return "COMP (Compression Header Protocol)";
    case IPPROTO_L2TP:
      return "L2TP (Layer 2 Tunnelling Protocol)";
    case IPPROTO_SCTP:
      return "SCTP (Stream Control Transmission Protocol)";
    case IPPROTO_UDPLITE:
      return "UDPLITE (UDP-Lite protocol)";
    case IPPROTO_MPLS:
      return "MPLS (MPLS in IP)";
    case IPPROTO_ETHERNET:
      return "ETHERNET (Ethernet-within-IPv6 Encapsulation)";
    case IPPROTO_RAW:
      return "RAW (Raw IP packets)";
    default:
      break;
  }
  return "Unknown IP Protocol";
}


const char* get_icmp_name(uint8_t type)
{
  switch (type)
  {
    case ICMP_ECHOREPLY:
      return "Echo reply";
    case ICMP_SOURCEQUENCH:
      return "Source quench";
    case ICMP_ECHO:
      return "Echo request";
    case ICMP_ROUTERSOLICIT:
      return "Router solicitation";
    case ICMP_TSTAMP:
      return "Time stamp request";
    case ICMP_TSTAMPREPLY:
      return "Time stamp reply";
    case ICMP_IREQ:
      return "Information request";
    case ICMP_IREQREPLY:
      return "Information reply";
    case ICMP_MASKREQ:
      return "Address mask request";
    case ICMP_EXTENDED_ECHO_REQUEST:
      return "Extended echo request";
    case ICMP_EXTENDED_ECHO_REPLY:
      return "Extended echo reply";
    case ICMP_UNREACH:
      return "Destination unreachable";
    default:
      break;
  }
  return "Unknown ICMP Type.";
}
