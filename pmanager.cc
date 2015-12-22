#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/epoll.h>
#include <pthread.h>
#include <errno.h>
#include "probe.h"
#include "pmanager.h"
#include "pmcprotocol.h"

CPManager& CPManager::Instance()
{
    static CPManager pmanager;
    return pmanager;
}

int CPManager::Initialize()
{
    // Command Recv Thread 관련 변수 초기화
    // 테스트용 
    m_CommandPort = 11111;
    m_DataPort = 11112;
    m_PMIpAddress = inet_addr("172.16.5.60");
    ////////////////////////////////////////////

    // epoll 생성
    m_EpollFd = epoll_create(100);
    if(m_EpollFd < 0)
    {
        fprintf(stderr, "Error: epoll_create Errno: %d\n", errno);
        return NULL;
    }
    // epoll 이벤트 저장 변수 생성
    m_EpollEvents = (struct epoll_event*)malloc(sizeof(epoll_event) * 20);

    // 설정 파일에서 초기화
    if(InitFromFile() < 0)
        return -1; 
    // 명령 수신 스레드 시작
    StartCommandLoop();
    // CommandPort 연결
    if(ConnectCommand() < 0)
        return -1;

    return 0;
}

// InitializeFromFile
// PManager 정보가 존재하는 파일에서 정보를 가져와서 초기화 시작
int CPManager::InitFromFile()
{
    // 지정된 위치(PMANAGER_CONFIGFILEPATH)경로의 파일 불러오기

    // 라인 단위로 읽어 pmanager 관련 변수 찾기

    return 0;
}

// ConnectCommand
// 커맨드 포트 연결
int CPManager::ConnectCommand()
{
    // 주소 셋팅
    struct sockaddr_in clientaddr;
    int clientlen;
    clientaddr.sin_family = AF_INET;
    clientaddr.sin_addr.s_addr = m_PMIpAddress;
    clientaddr.sin_port = htons(m_CommandPort);
    clientlen = sizeof(clientaddr);
    
    // 소켓 연결
    m_CommandSock = socket(AF_INET, SOCK_STREAM, 0);
    if(connect(m_CommandSock, (struct sockaddr*)&clientaddr, clientlen) < 0)
    {
        // 에러 처리
        fprintf(stderr, "Error: Connect Command Port Error errorno: %d\n", errno);
        return -1;
    }
    // 커맨드 이벤트 등록
    RegCommandSock();
    return 0;
}

void CPManager::DisconnectCommand()
{
    close(m_CommandSock);
}


// ConnectData
// 데이터 포트 연결 후 socket fd 반환
int CPManager::ConnectData()
{
    // 주소 셋팅
    struct sockaddr_in clientaddr;
    int clientlen;
    clientaddr.sin_family = AF_INET;
    clientaddr.sin_addr.s_addr = m_PMIpAddress;
    clientaddr.sin_port = htons(m_DataPort);
    clientlen = sizeof(clientaddr);

    // 소켓 연결
    m_DataSock = socket(AF_INET, SOCK_STREAM, 0);
    if(connect(m_DataSock, (struct sockaddr*)&clientaddr, clientlen) < 0)
    {
        // 에러 처리
        fprintf(stderr, "Error: Connect Data Port Error\n");
        return -1;
    }

    return 0;
}
void CPManager::DisconnectData()
{
    close(m_DataSock);
}

int CPManager::RegCommandSock()
{
    struct epoll_event ev;

    ev.events = EPOLLIN;
    ev.data.fd = m_CommandSock;
    if(epoll_ctl(m_EpollFd, EPOLL_CTL_ADD, m_CommandSock, &ev) == -1)
    {
        // EEXIST
        if(errno == EEXIST)
            printf("e\n");
        else if(errno == ENOSPC)
            printf("dd\n");
        else if(errno == EPERM)
            printf("eperm\n");
        else if(errno == ENOMEM)
            printf("enomem");
        else if(errno == EBADF)
            printf("ebadf");
        else
            printf("?\n");
        fprintf(stderr, "Error: epoll_ctl Errorno: %d\n", errno);
        return -1;
    }
    return 0;
}

void *CPManager::CommandLoop(void *data)
{
    printf("[epoll thread] Start command loop\n");
    // 커맨드 소켓 epoll 이벤트 등록
    int commandsockfd = CPManager::Instance().GetCommanSockfd();
    int efd = CPManager::Instance().GetEpollFd();
    epoll_event *events = CPManager::Instance().GetEpollEvents();
    int evnum;

    // epoll_wait 루프
    char recvbuf[1500];
    int recvnum;
    printf("[epoll thread]Command Loop Start\n");
    int sleepint = 0;
    while(CPManager::Instance().IsStopCommandLoop() == false) // 루프 탈출 플래그 감시 
    {
        // sleep 0
        if(sleepint++ > 100)
        {
            sleepint=0;
            sleep(0);
        }

        // epoll_wait
        evnum = epoll_wait(efd, events, 20, 1000);
        if(evnum == -1)
        {
            fprintf(stderr, "[epoll thread]Error: epoll_wait error, errno: %d\n", errno);
            if(errno == 4)
                continue;
            else
                return NULL;
        }
        // 이벤트 처리
        for(int i = 0; i < evnum ; i++)
        {
            // commans socket 이벤트 처리
            if(events[i].data.fd == commandsockfd)
            {
                memset(recvbuf, '\0', 1500);
                recvnum = read(events[i].data.fd, recvbuf, sizeof(PMCMessage));
                if(recvnum == sizeof(PMCMessage))
                {
                    PMCMessage *pmcmsg = (PMCMessage*)recvbuf;
                    if(pmcmsg->datalen != 0)
                        recvnum += read(events[i].data.fd, recvbuf + sizeof(PMCMessage), pmcmsg->datalen);
                    // 명령 실행
                    pea.ExcuteCommand(recvbuf);
                }
            }
            else
            {
                fprintf(stderr, "[epool Error]: other socket?, evsockfd:%d\n", events[i].data.fd);
            }
        }
    }
    printf("[epoll thread] End Command Loop\n");

}

void CPManager::StartCommandLoop()
{
    int thid; 
    // 시작 플래그 셋팅
    m_CommandThreadStop = false;

    // command recv thread 시작
    thid = pthread_create(&m_CommandRecvThread, NULL, CPManager::CommandLoop, NULL);
    if(thid < 0)
    {
        fprintf(stderr, "Error: pthread_create error\n");
        return ;
    }
}

void CPManager::EndCommandLoop()
{
    int status;
    int ret;
    // 정지 플래그 셋팅
    sleep(0);
    m_CommandThreadStop = true;

    // command recv thread 종료 기다리기
    ret = pthread_join(m_CommandRecvThread, (void **)&status);
    if(ret == 0)
    {
        printf("Completed join with thread status= %d\n", status);
    }
    else
    {
        printf("ERROR; return code from pthread_join() is %d, thread\n", ret);
    } 
}

PMCMessage CPManager::PopCommand()
{
    // 명령 받기
    PMCMessage cmd;
    if(m_DequeCommand.size() > 0)
    {
        //cmd = m_DequeCommand.at(0);
        m_DequeCommand.pop_front();
        return cmd;
    }
}

void CPManager::PushCommand(PMCMessage &cmd)
{
    m_DequeCommand.push_back(cmd);
}

int CPManager::SendMessage(const char *message, int messagelen)
{
    int ret; 
    // Command Port로 패킷 전송
    ret = write(m_CommandSock, message, messagelen);
    if(ret == -1)
    {
        fprintf(stderr, "Error: command write error, errno: %d\n", errno);
    }
    return ret;
}

int CPManager::SendData(const char *data, int datalen)
{
    // Data Port로 패킷 전송
    int ret = write(m_DataSock, data, datalen);
    if(ret == -1)
        fprintf(stderr, "Error: write error, errno: %d\n", errno);
    return ret;
}

void CPManager::Close()
{
    // probe stop command 전송
    pea.EndProbe();
    // 데이터 포트 연결 종료
    DisconnectData();
    // 명령 포트 연결 종료
    DisconnectCommand();
    // 명령 루프 스레드 종료
    EndCommandLoop();
}
