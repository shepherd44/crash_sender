#ifndef __PMANAGER_H__
#define __PMANAGER_H__

// probed 설정 파일 위치 및 인자
#define PMANAGER_CONFIGFILE_PATH        "/etc/pmanager.ini"
#define PMANAGER_CONFIGFILE_IPADDR      "pm_ipaddress"
#define PMANAGER_CONFIGFILE_COMMANDPORT "pm_port_command"
#define PMANAGER_CONFIGFILE_DATAPORT    "pm_port_data"

#include <stdint.h>
#include <deque>
#include <pthread.h>
#include <sys/epoll.h>
#include "pmcprotocol.h"

// Command 구조체
typedef struct Command
{
    uint16_t DataLen;
    uint8_t  OPCode;
    uint8_t  Flags;
}Command;

// PManager 클리스
// PManager와 연결되는 command, data socket관리
// PManager에게서 받은 Command 저장
// Probe가 해당 메시지 큐에서 명령을 받아간다.
// 커맨드 이벤트 리시브는 epoll을 통해 관리
// epoll을 통해 명령을 받는 이벤트 리시버는 스레드를 통해 단독 동작
// CPManager에 있는 커맨드 큐에 이벤트 저장
// CPManager는 명령 관리가 주가 됨
// 싱글톤으로 하나만 존재하도록 하고
// 오브젝트 반환 함수: GetSingleObject
class CPManager
{
private:
    // Pmanager Information
    uint32_t m_PMIpAddress;
    int m_CommandPort;
    int m_DataPort;
    int m_CommandSock;
    int m_DataSock;

    // PManager 명령 수신 thread 관리
    pthread_mutex_t m_CommandLock;
    pthread_t m_CommandRecvThread;
    bool m_CommandThreadStop;
    int m_EpollFd;
    epoll_event *m_EpollEvents;

    // PManager의 명령 저장 queue
    std::deque<PMCMessage> m_DequeCommand;
    bool m_IsEmptyCommand;

    // error 찾기용
    CPManager() {};
    // 복사 생성자, 오퍼레이터 제거
    CPManager(CPManager const&);// = delete;
    void operator=(CPManager const&);// = delete;
public:
    // singleton Object 반환 함수
    static CPManager& Instance();
public:

    // Connect socket
    int ConnectCommand();
    void DisconnectCommand();
    int RegCommandSock();
    // Data socket
    int ConnectData();
    void DisconnectData();

    // CPManager 명령 수신 관련 함수
    // 명령 루프 시작
    // epoll을 이용한 Command Recieve Thread 생성
    // Pmanager에게서 오는 명령을 받아 커맨드 큐에 저장
    void StartCommandLoop();
    bool IsStopCommandLoop() { return m_CommandThreadStop; }
    static void *CommandLoop(void *data);
    // 명령 루프 종료
    // Comman Recieve Thread 종료
    void EndCommandLoop();
    // 명령 큐에 남은 명령이 존재할 경우 뽑아서 반환
    PMCMessage PopCommand();
    void PushCommand(PMCMessage &cmd);

    // PManager에게 command 전달
    int SendMessage(const char * message, int messagelen);
    // PManager에게 Data 전달
    int SendData(const char* data, int datalen);

    int Initialize();
    // PManager 설정 파일로 초기화 진행
    int InitFromFile();

    // 종료
    void Close();
    // Get 함수
    int GetCommanSockfd() { return m_CommandSock; }
    int GetDataSockfd() {return m_DataSock; }
    int GetEpollFd() {return m_EpollFd; }
    epoll_event *GetEpollEvents() { return m_EpollEvents; }
};
#endif
