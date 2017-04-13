#define WIN32_LEAN_AND_MEAN
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/applink.c>
#include <winsock2.h>
#include <string>
#include <stdio.h>
#include <iostream>
#include <WS2tcpip.h>
#include <thread>
#include <regex>
#include<process.h>

#pragma comment (lib, "Ws2_32.lib")
#define BUFFER 70000 //tcp 패킷 최대 바이트 수
std::string getAddr(char *_data);
void checkArguments(int argc, char **argv);
std::string URLToAddrStr(std::string addr);
struct sockaddr_in initAddr(int port, std::string addr);
void initWSA();
void errorHandle(std::string msg, SOCKET s);
void forward(struct sockaddr_in serverAddr, SOCKET Client);
void open_socket(SOCKET &sock, struct sockaddr_in &sockaddr);
void certificate(SSL * ssl, int option);
int nonblock(SOCKET &fd, int num);

using namespace std;
SSL_CTX *clear_method(SSL_METHOD *method)
{
	SSL_library_init();
	OpenSSL_add_all_algorithms();
	SSL_load_error_strings();
	return SSL_CTX_new(method);
}

void load_certificate(SSL_CTX *ctx, string cert_path, string key_path)
{
	if (SSL_CTX_use_certificate_file(ctx, cert_path.c_str(), SSL_FILETYPE_PEM) <= 0)
	{
		ERR_print_errors_fp(stderr);
	}
	if (SSL_CTX_use_PrivateKey_file(ctx, key_path.c_str(), SSL_FILETYPE_PEM) <= 0)
	{
		ERR_print_errors_fp(stderr);
	}
	if (!SSL_CTX_check_private_key(ctx))
	{
		fprintf(stderr, "Private key does not match the public certificate\n");
	}
}

void certificate(SSL *ssl, int option)
{
	X509 *cert;
	char *str;
	if (option == 0)
	{
		cert = SSL_get_certificate(ssl);
		if (cert == NULL)
		{
			std::cout << "error : certificate not found" << std::endl;
		}
		else
		{
			str = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
			std::cout << "서버 인증서 :" << str << std::endl;
			str = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
			std::cout << "issuer : " << str << std::endl;
			OPENSSL_free(str);
			X509_free(cert);
		}
	}
	if (option == 1)
	{
		cert = SSL_get_peer_certificate(ssl);
		if (cert == NULL)
		{
			cout << "not get server certificate" << endl;
		}
		else
		{
			str = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
			std::cout << "호스트 인증서 :" << str << std::endl;
			str = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
			std::cout << "issuer : " << str << std::endl;
			OPENSSL_free(str);
			X509_free(cert);
		}
	}
}
int main(int argc, char **argv)
{
	checkArguments(argc, argv);
	initWSA();
	int port = atoi(argv[1]);
	struct sockaddr_in serverAddr = initAddr(port, std::string(""));
	SOCKET Client, Server;
	open_socket(Server, serverAddr); //소켓 생성 함수
	while (true)
	{

		if ((Client = accept(Server, NULL, NULL)) == INVALID_SOCKET)
		{
			printf("error : accept\n");
			continue;
		}
		std::thread(forward, serverAddr, Client).detach();
	}
	
}
//비동기 소켓 만드는 함수
int nonblock(SOCKET &fd, int num)
{
	unsigned long flags = num;
	return ioctlsocket(fd, FIONBIO, &flags); //소켓의 입출력 모드를 제어하는 함수이다.
											 //(s,cmd,argp) s: 작업대상 소켓의 기술자 명시 cmd : 소켓 s가 수행할 커맨드, argp : command에 대한 입 출력 파라메터로 사용
											 // flags 1 이면 비동기 모드 0 이면 동기 모드
}
std::string getAddr(char *_data)
{
	std::string data(_data);
	std::smatch result;
	std::regex pattern("Host: (.*)");
	if (std::regex_search(data, result, pattern))
	{
		return result[1];
	}
	return "";
}
void checkArguments(int argc, char **argv)
{
	if (!(argc <= 3 && argc >= 2))
	{
		printf("syntax : netserver <port>[-echo]\n");
		exit(0);
	}
}
std::string URLToAddrStr(std::string addr)
{
	struct addrinfo hints;
	struct addrinfo *result, *rp;
	struct sockaddr_in *sin;
	int *listen_fd;
	int listen_fd_num = 0;
	char buf[80] = { 0x00, };
	int i = 0;
	memset(&hints, 0x00, sizeof(struct addrinfo));
	hints.ai_flags = AI_PASSIVE;
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	if (getaddrinfo(addr.c_str(), NULL, &hints, &result) != 0) {
		perror("getaddrinfo");
		return std::string("");
	}
	for (rp = result; rp != NULL; rp = rp->ai_next)
	{
		listen_fd_num++;
	}
	listen_fd = (int *)malloc(sizeof(int)*listen_fd_num);
	for (rp = result, i = 0; rp != NULL; rp = rp->ai_next, i++)
	{
		if (rp->ai_family == AF_INET)
		{
			sin = (sockaddr_in *)rp->ai_addr;
			inet_ntop(rp->ai_family, &sin->sin_addr, buf, sizeof(buf));
			return std::string(buf);
		}
	}
	return NULL;
}
struct sockaddr_in initAddr(int port, std::string addr)
{
	struct sockaddr_in newAddr;
	ZeroMemory(&newAddr, sizeof(newAddr));
	newAddr.sin_family = AF_INET;
	newAddr.sin_port = htons(port);
	if (addr.empty()) {
		newAddr.sin_addr.s_addr = htonl(INADDR_ANY);
	}
	else {
		inet_pton(AF_INET, addr.c_str(), &newAddr.sin_addr.s_addr);
	}
	return newAddr;
}
void initWSA() {
	WSADATA wsaData;
	if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
		printf("Error : Initialize Winsock\n");
		WSACleanup();
		exit(0);
	}
}
void errorHandle(std::string msg, SOCKET s) {
	std::cerr << "ERROR : " << msg;
	if (s != NULL) {
		closesocket(s);
	}
	WSACleanup();
	exit(0);
}

void ssl_backward(SOCKET Client, SOCKET RemoteSocket ,SSL *Remote_SSL)
{
	char buf[BUFFER];
	char *remotebuf;
	int recvlen;
	unsigned long flags = 1;
	while((recvlen = recv(RemoteSocket, buf, BUFFER, 0)) > 0)
	{
		std::cout << "수신완료" << endl;
		if (recvlen == SOCKET_ERROR)
		{
			std::cout << "error : backward recv()" << endl;
			continue;
		}
		remotebuf = (char *)calloc(recvlen, sizeof(recvlen));
		memcpy(remotebuf, buf, recvlen);
		cout << "웹 내용" << endl;
		cout << remotebuf << endl;
		if (send(Client, remotebuf, recvlen, 0) == SOCKET_ERROR) 
		{
			printf("send to client failed.");
			continue ;
		}

	}
	while ((recvlen = SSL_read(Remote_SSL, buf, BUFFER)) > 0)
	{
		std::cout << "수신완료" << endl;
		if (recvlen == SOCKET_ERROR)
		{
			std::cout << "error : backward recv()" << endl;
			continue;
		}
		remotebuf = (char *)calloc(recvlen, sizeof(recvlen));
		memcpy(remotebuf, buf, recvlen);
		cout << "암호화 웹 내용" << endl;
		cout << remotebuf << endl;
		if (send(Client, remotebuf, recvlen, 0) == SOCKET_ERROR)
		{
			printf("send to client failed.");
			continue;
		}
	}
	std::cout << "클라이언트로 전송완료" << endl;
}

void forward(struct sockaddr_in serverAddr, SOCKET Client)
{
	int port = 443;
	char buf[BUFFER];
	char *recvbuf;
	int recvbuflen;
	std::string hostAddr, domainip;
	SOCKET RemoteSocket;
	struct sockaddr_in remoteAddr;
	SSL *client_ssl;
	SSL_CTX *client_ctx = clear_method((SSL_METHOD *)SSLv23_client_method());
	if (client_ctx == NULL)
	{
		cout << "client ctx error";
		//break;
	}
	load_certificate(client_ctx, "C:/Program Files/SnoopSpy/certificate/default.crt", "C:/Program Files/SnoopSpy/certificate/default.key");
	memset(buf, NULL, BUFFER);
	while ((recvbuflen = recv(Client, buf, BUFFER, 0)) > 0)
	{
		if (recvbuflen == SOCKET_ERROR)
		{
			cout << "recv error " << endl;
			return;
		}
		recvbuf = (char *)calloc(recvbuflen - 1, sizeof(char));
		memcpy(recvbuf, buf, recvbuflen - 1);
		cout << "클라이언트 요청" << endl;
		cout << recvbuf << endl;
		if (strstr(recvbuf, "CONNECT") != NULL)
		{
			hostAddr = getAddr(recvbuf); //여기서 443 포트 번호 확인해야한다.
			cout << "site :" << hostAddr << endl;

			if (hostAddr == "")
			{
				printf("Empty Host Address..\n");
				return;
			}
			else
				domainip = URLToAddrStr(hostAddr);
			if (domainip == "")
			{
				return;
			}
		}
		cout << "Domain IP :" << domainip << endl;
		remoteAddr = initAddr(port, domainip); //포트와 도메인 소켓에 넣기
		if ((RemoteSocket = socket(PF_INET, SOCK_STREAM, 0)) == INVALID_SOCKET)
		{
			errorHandle("ERROR : Create a Socket for conneting to server\n", NULL);
		}
		cout << "REMOTE SOCKET Create" << endl;
		if (connect(RemoteSocket, (struct sockaddr*) &remoteAddr, sizeof(remoteAddr)) == SOCKET_ERROR)
		{
			std::cout << "연결실패" << endl;
			//break;
		}
		std::cout << "remote 연결" << endl;
		std::thread(ssl_backward, Client, RemoteSocket, client_ssl).detach();
		if ((client_ssl = SSL_new(client_ctx)) == NULL)
		{
			cout << "ssl is empty" << endl;
		}
		if (send(RemoteSocket, recvbuf, recvbuflen, 0) == SOCKET_ERROR)
		{
			cout << "HTTP CONNECT fail" << endl;
			continue;

		}
		cout << "remote HTTPCONNECT METHOD sending" << endl;
		SSL_set_fd(client_ssl, RemoteSocket);
		if (SSL_connect(client_ssl) == NULL)
		{
			cout << " ssl not connect" << endl;
			return;
		}
		cout << "3handshake" << endl;
	}
}

void open_socket(SOCKET &sock, struct sockaddr_in &sockaddr)
{
	if ((sock = socket(PF_INET, SOCK_STREAM, 0)) == INVALID_SOCKET) {
		errorHandle("ERROR : Create a Socket for connetcting to server\n", NULL);
	}
	if (::bind(sock, (struct sockaddr*)&sockaddr, sizeof(sockaddr)) != 0) {
		errorHandle("ERROR : Setup the TCP Listening socket\n", sock);
	}
	if (listen(sock, SOMAXCONN) == SOCKET_ERROR) {
		errorHandle("ERROR : Listen\n", sock);
	}
}
