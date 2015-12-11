#include <stdlib.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <iostream>
#include <vector>

#include "pmanager.h"
#include "probe.h"
#include "pcap.h"

#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <exception>
#define PROMISCUOUS     1
#define NONPROMISCUOUS  0
#define DEV_MAX         32

typedef struct _pcd_info_t
{
    int     num;
    char    name[DEV_MAX][16];
    pcap_t  *pcd;
    u_long  out_size[DEV_MAX];
    u_long  out_pkts[DEV_MAX];
    u_long  in_size[DEV_MAX];
    u_long  in_pkts[DEV_MAX];
} pcd_info_t;


int main(int argc, char** argv)
{
    std::cout << "probe daemon start" << std::endl;
    pid_t pid;
    CPManager pm(100,1111,1111);
    CProbe pea();

    char errbuf[PCAP_ERRBUF_SIZE];
    memset(errbuf, '\0', PCAP_ERRBUF_SIZE);
    pcd_info_t lpcd_info;
    pcap_if_t *alldevps;
    struct sockaddr_in *si;
    int i;

    memset((void *)&lpcd_info, 0x00, sizeof(lpcd_info));
    if( pcap_findalldevs(&alldevps, errbuf) == -1)
    {
        std::cout << "error: " << errbuf << std::endl;
        return -1;
    }

    while(1)
    {
            if(alldevps->addresses == NULL)
            {
                si = 0;
            }
            else
            {
               // si = (struct sockaddr *)alldevps->addresses->addr;
                si = (struct sockaddr_in *)alldevps->addresses->addr;
                printf("addr:%s ", alldevps->addresses->addr->sa_data);
                printf("addrfamilly: %d ", si->sin_family);
//                printf("addr:%s ", si->sin_addr);
            }
            
            printf("%d %s %s\n", alldevps->flags, alldevps->name, si == 0 ? "" : inet_ntoa(si->sin_addr));
        if (alldevps->next == NULL)
            break;
        alldevps = alldevps->next;
    }

    // socket에서 인터페이스 정보 얻기
    //  /usr/include/bits/ioctls.h 
    //#define SIOCGIFNAME     0x8910          [> get iface name               <]
    //#define SIOCSIFLINK     0x8911          [> set iface channel            <]
    //#define SIOCGIFCONF     0x8912          [> get iface list               <]
    //#define SIOCGIFFLAGS    0x8913          [> get flags                    <]
    //#define SIOCSIFFLAGS    0x8914          [> set flags                    <]
    //#define SIOCGIFADDR     0x8915          [> get PA address               <]
    //#define SIOCSIFADDR     0x8916          [> set PA address               <]
    //#define SIOCGIFDSTADDR  0x8917          [> get remote PA address        <]
    //#define SIOCSIFDSTADDR  0x8918          [> set remote PA address        <]
    //#define SIOCGIFBRDADDR  0x8919          [> get broadcast PA address     <]
    //#define SIOCSIFBRDADDR  0x891a          [> set broadcast PA address     <]
    //#define SIOCGIFNETMASK  0x891b          [> get network PA mask          <]
    //#define SIOCSIFNETMASK  0x891c          [> set network PA mask          <]
    //#define SIOCGIFMETRIC   0x891d          [> get metric                   <]
    //#define SIOCSIFMETRIC   0x891e          [> set metric                   <]
    //#define SIOCGIFMEM      0x891f          [> get memory address (BSD)     <]
    //#define SIOCSIFMEM      0x8920          [> set memory address (BSD)     <]
    //#define SIOCGIFMTU      0x8921          [> get MTU size                 <]
    //#define SIOCSIFMTU      0x8922          [> set MTU size                 <]
    //#define SIOCSIFNAME     0x8923          [> set interface name           <]
    //#define SIOCSIFHWADDR   0x8924          [> set hardware address         <]
    int fd;
    fd = socket(AF_INET, SOCK_DGRAM, 0);
    struct ifconf ifconfig;
    int numreq = 30;
    memset(&ifconfig, 0, sizeof(struct ifconf));
    struct ifreq *ifr;
    struct sockaddr_in *sin;
    ifconfig.ifc_len = sizeof(struct ifreq) * numreq;
    //ifconfig.ifc_buf = (char *)malloc(ifconfig.ifc_len);

    printf("dd");
    for(;;)
    {
        //ifconfig.ifc_len = sizeof(struct ifreq) * numreq;
        if (ioctl(fd, SIOCGIFCONF, (char *)&ifconfig) < 0)
        {
            perror("SIOCGIFCONF ");
            exit;
        }
        ifconfig.ifc_buf = (char *)malloc(ifconfig.ifc_len);
        if (ioctl(fd, SIOCGIFCONF, (char *)&ifconfig) < 0)
        {
            perror("SIOCGIFCONF ");
            exit;
        }
        printf("len: %d, addr: %d\n", ifconfig.ifc_len, (unsigned long)ifconfig.ifc_buf);
        break;
    }
    int nicnum = ifconfig.ifc_len / sizeof(ifreq);
    for(int i = 0; i < nicnum ; i++)
    {
        struct ifreq *temp = &ifconfig.ifc_req[i];
        printf("name: %s\n", temp->ifr_name);
        ioctl(fd, SIOCGIFHWADDR, temp);
        printf("MAC : %s\n", temp->ifr_hwaddr.sa_data);
        ioctl(fd, SIOCSIFADDR, temp);
        sin = (sockaddr_in *)&temp->ifr_addr;
        printf("ip  : %s\n", inet_ntoa(sin->sin_addr));
        ioctl(fd, SIOCGIFNETMASK, temp);
        sin = (sockaddr_in *)&temp->ifr_addr;
        printf("mask: %s\n", inet_ntoa(sin->sin_addr));
        ioctl(fd, SIOCGIFMTU, temp);
        printf("MTU : %d\n\n", temp->ifr_mtu);
    }
        //struct ifreq temp;
        //memset(&temp, 0, sizeof(struct ifreq));
        //strcpy(temp.ifr_name,"eth3");
        //printf("name: %s\n", temp.ifr_name);
        //ioctl(fd, SIOCGIFHWADDR, temp);
        //printf("MAC : %s\n", temp.ifr_hwaddr.sa_data);
        //ioctl(fd, SIOCSIFADDR, temp);
        //sin = (sockaddr_in *)&temp.ifr_addr;
        //printf("ip  : %s\n", inet_ntoa(sin->sin_addr));
        //ioctl(fd, SIOCGIFNETMASK, temp);
        //sin = (sockaddr_in *)&temp.ifr_addr;
        //printf("mask: %s\n", inet_ntoa(sin->sin_addr));
        //ioctl(fd, SIOCGIFMTU, temp);
        //printf("MTU : %d\n\n", temp.ifr_mtu);
}
