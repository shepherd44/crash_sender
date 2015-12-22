#include <iostream>
#include <vector>
#include <exception>

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>

#include "pmanager.h"
#include "sniffer.h"
#include "probe.h"
#include "pcap.h"
#include "pmcprotocol.h"

#define PROMISCUOUS     1
#define NONPROMISCUOUS  0
#define DEV_MAX         32

// Probe 전역 변수

int main(int argc, char** argv)
{
    int ret;
    // Daemon 형태의 프로그램 작성
    // 메인 thread는 명령 실행 thread로 사용
    // 생성할 thread: Command recv thread, send thread
    std::cout << "============== probe daemon start ==============" << std::endl;
    pid_t pid;

    // probe 디바이스 찾기
    printf("[main] NIC List Initialize\n");
    pea.FindNetDevice();
    // 매니저 초기화(커맨드, 데이터 포트 연결)
    // 명령 수신 스레드 생성
    printf("[main] pmanager Initialize\n");
    CPManager::Instance().Initialize();

    // SnifferLoop 초기화(thread 생성)
    g_SnifferLoop.CreateCaptureThread();
    
    sleep(0);
    // Connect Message 전송
    printf("[main] probe Connect message send\n");
    pea.StartProbe();

    //////////////////////////////////////
    // test sniffer
    //sleep(1);
    //CNIC nic((char*)"eth2", NULL);
    //nic.Refresh();
    //ret = g_SnifferLoop.CreateSniffer(nic.GetNICName(), nic.GetMACAddr(), nic.GetNICAddr()->netmask);
    //printf("ret: %d\n", ret);
    //sleep(5);
    //ret = g_SnifferLoop.RemoveSniffer(nic.GetNICName(), strlen(nic.GetNICName()));
    //printf("ret: %d\n", ret);


    //CSniffer s(nic.GetNICName(), nic.GetMACAddr(), nic.GetNICAddr()->netmask);
    //s.StartCapture();

    //sleep(1);
    //uint8_t data[3000];
    //memset(data, 0, 3000);
    //struct pcap_pkthdr h;
    //uint32_t l;
    //int ii = 0;
    //printf("[main] packet capture start\n");
    ////while(ii < 5)
    //while(1)
    //{
        //sleep(0);
        //l = s.GetNextPacket((uint8_t*)data, &h);
        //if(l == 0)
            //continue;
        //else
            //ii++;
        
        //CPManager::Instance().SendData((char *)data, h.len + 30);
        ////printf("=");
        ////for(int i=0; i< 10; i++)
            ////printf("%02x ", (uint8_t)data[i]);
        //printf("\n=send raw packet, length = %d\n", h.len + 30);
        ////break;
    //}
    //printf("[main] packet capture end\n");

    //ii = 0;
    //sleep(1);
    
    while(1)
    {
        sleep(1);
    }
    //////////////////////////////////

    // 종료
    g_SnifferLoop.StopCaptureThread();
    printf("[main] Disconnect Message Send\n");
    CPManager::Instance().Close();
    std::cout << "=============== probe daemon end ===============" << std::endl;
}
