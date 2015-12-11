#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "inetproto.h"

// Checksum
// 헤더 길이는 바이트 단위
uint16_t IPHeaderChecksum(uint16_t iph_len, uint8_t *piph)
{
    uint16_t sum = 0;

    // 2바이트 단위로 더하므로 iph_len/2
    //iph_len >>= 1;
    for (uint16_t i = 0; i < iph_len; i += 2)
    {
        uint16_t word = ((piph[i] << 8) + (piph[i + 1]));
        uint16_t carry = 65535 - sum;
        sum += word;
        if (word > carry){ sum += 1; }
    }
    // 1의 보수
    sum = ~sum;

    return sum;
}

void SetARPPacket(uint8_t *out,
        uint8_t htype,
        uint8_t ptype,
        uint8_t hlen,
        uint8_t plen,
        uint16_t opcode,
        uint8_t *srcmac,
        uint8_t *srcip,
        uint8_t *dstmac,
        uint8_t *dstip
        )
{
    ARPPacket arppacket;
    memset(&arppacket, 0, sizeof(ARPPacket));
    int arplen = sizeof(ARPPacket);

    // arppacket 만들기
    arppacket.htype = htype;    // 하드웨어 타입
    arppacket.ptype = ptype;    // 프로토콜 타입
    arppacket.hlen = hlen;      // 하드웨어 주소 길이
    arppacket.plen = plen;      // 프로토콜 주소 길이
    arppacket.opcode = opcode;  // ARP OPCODE
    memcpy(arppacket.shaddr, srcmac, MACADDRESS_LENGTH);    // 송신지 하드웨어 주소 설정
    memcpy(arppacket.spaddr, srcip, IPV4ADDRESS_LENGTH);    // 송신지 IP address 셋팅
    memcpy(arppacket.dhaddr, dstmac, MACADDRESS_LENGTH);    // 목적지 하드웨어 주소 설정
    memcpy(arppacket.dpaddr, dstip, IPV4ADDRESS_LENGTH);    // 목적지 ip address 셋팅

    // 패킷 셋팅
    memcpy(out, &arppacket, arplen);
}
