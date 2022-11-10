#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "token.h"
int main(){
    struct sockaddr_in mysock;
    ngx_str_t token;
 

    bzero(&mysock,sizeof(mysock));  //初始化结构体
    mysock.sin_family = AF_INET;  //设置地址家族
    mysock.sin_port = htons(800);  //设置端口
    mysock.sin_addr.s_addr = inet_addr("192.168.1.0");  //设置地址


    memset(&token, 0, sizeof(token));

    ngx_quic_new_token(NULL, (struct sockaddr*)&mysock, sizeof(mysock), NULL, &token, NULL, 10, 1);

    return 0;
}
