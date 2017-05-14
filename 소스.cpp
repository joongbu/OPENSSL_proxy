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
#define PATH "C:\\Program Files\\SnoopSpy\\certificate\\" //인증서 경로
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
int main(int argc, char **argv)
{
	CheckArguments(argc, argv);
	SSL_run("", "8080");


}
void run(char *host, char *useport)
{
	InitWSA();
	int port = atoi(useport);
	struct sockaddr_in serverAddr;
	cout << host << endl;
	cout << useport << endl;
	cout << port << endl;
	serverAddr = InitAddr(port, host);

	SOCKET Client, Server;
	Open_socket(Server, serverAddr); //소켓 생성 함수
	while (true)
	{
		if ((Client = accept(Server, NULL, NULL)) == INVALID_SOCKET) {
			printf("error : accept\n");

		}
		std::thread(Forward, serverAddr, Client).detach();
	}
}
string GetAddr(char *_data)
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

void CheckArguments(int argc, char **argv)
{
	if (!(argc <= 3 && argc >= 2))
	{
		printf("syntax : netserver <port>[-echo]\n");
		exit(0);
	}
}
string URLToAddrStr(std::string addr)
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
		return "";
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

			return string(buf);
		}
	}
	return "";
}

struct sockaddr_in InitAddr(int port, std::string addr)
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

void InitWSA() {
	WSADATA wsaData;
	if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
		printf("Error : Initialize Winsock\n");
		WSACleanup();
		exit(0);
	}
}

void ErrorHandle(std::string msg, SOCKET s) {
	std::cerr << "ERROR : " << msg;
	if (s != NULL) {
		closesocket(s);
	}
	WSACleanup();
	exit(0);
}

void Backward(SOCKET Client, SOCKET RemoteSocket)
{
	char buf[BUFFER];
	int recvlen;
	memset(buf, NULL, BUFFER);
	while ((recvlen = recv(RemoteSocket, buf, BUFFER, 0)) > 0)//타임아웃 걸기
	{
		if (send(Client, buf, recvlen, 0) == SOCKET_ERROR) {
			printf("send to client failed.");
			continue;
		}
	}
}
void Forward(struct sockaddr_in serverAddr, SOCKET Client)
{
	int port = 80;
	char buf[BUFFER];
	int recvbuflen;
	std::string hostAddr, domainip;
	SOCKET RemoteSocket;
	struct sockaddr_in remoteAddr;
	memset(buf, NULL, BUFFER);
	while ((recvbuflen = recv(Client, buf, BUFFER, 0)) > 0)
	{
		if (strstr(buf, "CONNECT") != NULL)
			continue;
		hostAddr = GetAddr(buf);
		cout << buf << endl;
		cout << hostAddr << endl;
		if (hostAddr == "")
		{
			printf("Empty Host Address..\n");
			continue;
		}
		else
			domainip = URLToAddrStr(hostAddr);
		if (domainip == "")
		{
			break;
		}
		remoteAddr = InitAddr(port, domainip);
		if ((RemoteSocket = socket(PF_INET, SOCK_STREAM, 0)) == INVALID_SOCKET) {
			ErrorHandle("ERROR : Create a Socket for conneting to server\n", NULL);
		}
		if (connect(RemoteSocket, (struct sockaddr*) &remoteAddr, sizeof(remoteAddr)) == SOCKET_ERROR)
		{
			std::cout << "연결실패" << endl;
			break;
		}
		std::thread(Backward, Client, RemoteSocket).detach();

		if (send(RemoteSocket, buf, recvbuflen, 0) == SOCKET_ERROR)
		{
			printf("send to webserver failed.");
			memset(buf, NULL, BUFFER);
			continue;
		}
		memset(buf, NULL, BUFFER);
	}
}
void Open_socket(SOCKET &sock, struct sockaddr_in &sockaddr)
{
	if ((sock = socket(PF_INET, SOCK_STREAM, 0)) == INVALID_SOCKET) {
		ErrorHandle("ERROR : Create a Socket for connetcting to server\n", NULL);
	}
	if (::bind(sock, (struct sockaddr*)&sockaddr, sizeof(sockaddr)) != 0) {
		ErrorHandle("ERROR : Setup the TCP Listening socket\n", sock);
	}
	if (listen(sock, SOMAXCONN) == SOCKET_ERROR) {
		ErrorHandle("ERROR : Listen\n", sock);
	}
}
void SSL_backward(SSL *serverssl, SSL *remote_ssl)
{
	char buf[BUFFER];
	int buflen;
	memset(buf, NULL, BUFFER);
	while ((buflen = SSL_read(remote_ssl, buf, BUFFER)) > 0)
	{
		cout << buf << endl;
		EnterCriticalSection(&cs);
		if (SSL_write(serverssl, buf, buflen) == SOCKET_ERROR)
		{
			printf("ssl packet send to client failed.");
			LeaveCriticalSection(&cs);
			continue;
		}
		LeaveCriticalSection(&cs);
		memset(buf, NULL, BUFFER);
	}
}
int Servernamecallback(SSL *ssl, int *ad, void *arg)
{
	SSL_CTX *ctx = Clear_method((SSL_METHOD *)SSLv23_method());;
	string bat;
	string init = "_init_site.bat";
	string pem;
	bat += "_make_site.bat ";
	if (ssl == NULL)
		return SSL_TLSEXT_ERR_NOACK;
	const char* servername = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
	cout << "Host :" << servername << endl;
	bat += servername;
	pem += servername;
	pem += ".pem";
	_chdir(PATH);
	EnterCriticalSection(&cs);
	if (_access(pem.c_str(), 0) != 0)
	{
		if (system(bat.c_str()) != 0)
		{
			cout << "make site 삽입 실패" << endl;
		}

	}
	Load_certificate(ctx, pem, pem);
	//인증서 확인
	//certificate(ssl, 0);
	SSL_set_SSL_CTX(ssl, ctx);
	LeaveCriticalSection(&cs);
	return SSL_TLSEXT_ERR_NOACK;
}
void SSL_forward(struct sockaddr_in serverAddr, SOCKET Client, SSL *server_ssl)
{

	int port = 443;
	char buf[BUFFER];
	int buflen = 0;
	string hostAddr, domainip;
	SOCKET RemoteSocket;
	struct sockaddr_in remoteAddr;
	SSL *client_ssl;
	string default_certificate;
	string server_certificate;
	SSL_CTX *client_ctx = Clear_method((SSL_METHOD *)SSLv23_client_method());
	SSL_CTX *server_ctx = Clear_method((SSL_METHOD *)SSLv23_method());//SSL_CTX()
	server_certificate += PATH;
	/*
	default_certificate += PATH;
	default_certificate += "default.pem";
	*/
	if (!server_ctx)
	{
		ERR_print_errors_fp(stderr);
		std::cout << "Server ctx error";
		return;
	}
	if (!client_ctx)
	{
		ERR_print_errors_fp(stderr);
		cout << "client ctx error";
		return;
	}
	memset(buf, NULL, BUFFER);
	if ((buflen = recv(Client, buf, BUFFER, 0)) > 0)
	{
		if (strstr(buf, "CONNECT") != NULL)
		{
			send(Client, "HTTP/1.0 200 Connection established\r\n\r\n", strlen("HTTP/1.0 200 Connection established\r\n\r\n"), 0);
			memset(buf, NULL, BUFFER);
		}
	}

	EnterCriticalSection(&cs);
	if ((server_ssl = SSL_new(server_ctx)) == NULL)
	{
		std::cout << "SSL NULL" << std::endl;
	}
	LeaveCriticalSection(&cs);
	if (!SSL_CTX_set_tlsext_servername_callback(server_ctx, Servernamecallback))
	{
		cout << "ssl_ctx_set_tlsext_servername_callback return false" << endl;
	}

	if (!SSL_CTX_set_tlsext_servername_arg(server_ctx, NULL))
	{
		cout << "ssl_ctx_set_tlsext_servername_arg return false" << endl;

	}

	EnterCriticalSection(&cs);
	SSL_set_fd(server_ssl, Client);
	LeaveCriticalSection(&cs);
	if (SSL_accept(server_ssl) == -1)
	{
		cout << "accept Error" << endl;
		return;
	}
	cout << "ssl_accept success" << endl;


	hostAddr = SSL_get_servername(server_ssl, TLSEXT_NAMETYPE_host_name);
	if (hostAddr == "")
	{
		return;
		//load_certificate(client_ctx, default_certificate, default_certificate);
	}
	server_certificate += hostAddr;
	server_certificate += ".pem";
	domainip = URLToAddrStr(hostAddr);
	if (domainip == "")
	{
	}
	if ((RemoteSocket = socket(PF_INET, SOCK_STREAM, 0)) == INVALID_SOCKET)
	{
		ErrorHandle("ERROR : Create a Socket for conneting to server\n", NULL);
	}
	remoteAddr = InitAddr(port, domainip); //포트와 도메인 소켓에 넣기 
	if (connect(RemoteSocket, (struct sockaddr*) &remoteAddr, sizeof(remoteAddr)) == SOCKET_ERROR)
	{
		ErrorHandle("Connect Socket err", RemoteSocket);
		//break;
	}
	if ((client_ssl = SSL_new(client_ctx)) == NULL)
	{
		cout << "ssl is empty" << endl;
	}
	SSL_set_fd(client_ssl, RemoteSocket);
	if (SSL_connect(client_ssl) == NULL)
	{
		cout << " ssl not connect" << endl;

	}
	memset(buf, NULL, BUFFER);
	std::thread(SSL_backward, server_ssl, client_ssl).detach();
	EnterCriticalSection(&cs);
	while ((buflen = SSL_read(server_ssl, buf, BUFFER)) > 0)
	{
		LeaveCriticalSection(&cs);

		cout << buf << endl;
		if (SSL_write(client_ssl, buf, buflen) == SOCKET_ERROR)
		{
			printf("send to webserver failed.");
			continue;
		}
		memset(buf, NULL, BUFFER);
	}
	LeaveCriticalSection(&cs);
}
SSL_CTX *Clear_method(SSL_METHOD *method)
{
	SSL_library_init();
	OpenSSL_add_all_algorithms();
	SSL_load_error_strings();
	return SSL_CTX_new(method);

}
void Load_certificate(SSL_CTX *ctx, string cert_path, string key_path)
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
void Certificate(SSL *ssl, int option)
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
void SSL_run(char *host, char * str_port)
{
	InitWSA();
	int port = atoi(str_port);
	struct sockaddr_in serverAddr = InitAddr(port, std::string(host));
	SOCKET Client, Server;
	Open_socket(Server, serverAddr);	//소켓 생성 함수 
	SSL *server_ssl;
	InitializeCriticalSection(&cs);
	while (true)
	{

		if ((Client = accept(Server, NULL, NULL)) == INVALID_SOCKET)
		{
			printf("error : accept\n");
		}
		std::thread(SSL_forward, serverAddr, Client, server_ssl).detach();

	}
	DeleteCriticalSection(&cs);
}