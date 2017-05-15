#pragma once
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <string>
#include <stdio.h>
#include <iostream>
#include <WS2tcpip.h>
#include <thread>
#include <regex>
#include<process.h>
#include <fcntl.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/applink.c>
#include <stdlib.h>
#include <algorithm>
#include <cassert>
#include <direct.h> //path
#include <io.h> //access
#define PATH "C:\\certificate\\" //인증서 경로
#pragma comment (lib, "Ws2_32.lib")
#define BUFFER 5000 //tcp 패킷 최대 바이트 수
using namespace std;
string GetAddr(char *_data);
void CheckArguments(int argc, char **argv);
string URLToAddrStr(std::string addr);
struct sockaddr_in InitAddr(int port, std::string addr);
void InitWSA();
void ErrorHandle(std::string msg, SOCKET s);
void Backward(SOCKET Client, SOCKET RemoteSocket);
void Forward(struct sockaddr_in serverAddr, SOCKET Client);
void Open_socket(SOCKET &sock, struct sockaddr_in &sockaddr);
void run(char *host, char *useport);
void SSL_forward(struct sockaddr_in serverAddr, SOCKET Client, SSL *server_ssl);
void SSL_run(char *host, char * str_port);
SSL_CTX *Clear_method(SSL_METHOD *method);
void Load_certificate(SSL_CTX *ctx, string cert_path, string key_path);
void Certificate(SSL *ssl, int option);
CRITICAL_SECTION cs;
bool Stop = false;
