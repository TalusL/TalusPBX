#include <iostream>
#include "UserAgentSession.h"
#include <Network/UdpServer.h>
#include <csignal>
#include "AgentMgr.h"

using namespace toolkit;
int main() {
    //设置日志
    Logger::Instance().add(std::make_shared<ConsoleChannel>("ConsoleChannel", LTrace));

    UdpServer::Ptr sipServer = std::make_shared<UdpServer>();
    sipServer->start<UserAgentSession>(5060);

    AgentMgr::Instance().Start();

    //设置退出信号处理函数
    static semaphore sem;
    signal(SIGINT, [](int) {
        InfoL << "SIGINT:exit";
        signal(SIGINT, SIG_IGN); // 设置退出信号
        sem.post();
    }); // 设置退出信号
    sem.wait();

    return 0;
}
