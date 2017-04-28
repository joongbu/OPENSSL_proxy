#define WIN32_LEAN_AND_MEAN
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/applink.c>
#include <winsock2.h>
#include <string>
#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <WS2tcpip.h>
#include <thread>
#include <regex>
#include <algorithm>
#include <cassert>
#include<process.h>
#include <direct.h> //path
#include <io.h> //access
#define PATH "C:\\Program Files\\SnoopSpy\\certificate\\"
#pragma comment (lib, "Ws2_32.lib")
#define BUFFER 2000 //tcp 패킷 최대 바이트 수 
std::string getAddr(char *_data);
void checkArguments(int argc, char **argv);
std::string URLToAddrStr(std::string addr);
struct sockaddr_in initAddr(int port, std::string addr);
void initWSA();
void errorHandle(std::string msg, SOCKET s);
void ssl_forward(struct sockaddr_in serverAddr, SOCKET Client, SSL *server_ssl);
void open_socket(SOCKET &sock, struct sockaddr_in &sockaddr);
int nonblock(SOCKET &fd, int num);
using namespace std;
CRITICAL_SECTION cs;
int index;
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
	SSL *server_ssl;	
	while(true)
	{
		if ((Client = accept(Server, NULL, NULL)) == INVALID_SOCKET)
		{
			printf("error : accept\n");
			continue;
		}
		cout << "접속요청" << endl;
		std::thread(ssl_forward, serverAddr, Client, server_ssl).join();
	}
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
	if (getaddrinfo(addr.c_str(), NULL, &hints, &result) != 0)
	{
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
void ssl_backward(SSL *serverssl, SSL *remote_ssl)
{
	char buf[BUFFER];
	char *remotebuf;
	int recvlen;
	EnterCriticalSection(&cs);
	while ((recvlen = SSL_read(remote_ssl, buf, BUFFER)) > 0)
	{
		std::cout << "Back ward byte :" << recvlen << endl;;
		std::cout << "수신완료" << endl;
		if (recvlen == 0)
		{
			std::cout << "error : ssl backward recv()" << endl;
			continue;
		}
		remotebuf = (char *)calloc(recvlen, sizeof(recvlen));
		memcpy(remotebuf, buf, recvlen);
		cout << remotebuf << endl;
		if (SSL_write(serverssl, remotebuf, recvlen) == SOCKET_ERROR)
		{
			printf("ssl packet send to client failed.");
			break;
		}
		cout << "클라이언트로 보냄" << endl;
		memset(buf, NULL, BUFFER);
	}
	LeaveCriticalSection(&cs);
	std::cout << "클라이언트로 전송완료" << endl;
	std::cout << " 쓰레드 종료" << endl;

}

int servernamecallback(SSL *ssl, int *ad, void *arg)
{
	SSL_CTX *ctx = clear_method((SSL_METHOD *)SSLv23_method());;
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
	if (_access(pem.c_str(), 0) == 0)
	{
		cout << "같은 파일 존재" << endl;

	}
	else
	{
		
		if (system(bat.c_str()) != 0)
		{
			cout << "make site 삽입 실패" << endl;
		}
		
	}
	load_certificate(ctx, pem, pem);
	//certificate(ssl, 0);
	SSL_set_SSL_CTX(ssl, ctx);
	LeaveCriticalSection(&cs);
	
	return SSL_TLSEXT_ERR_NOACK;

}


void ssl_forward(struct sockaddr_in serverAddr, SOCKET Client, SSL *server_ssl)
{

	int port = 443;
	char buf[BUFFER];
	char *recvbuf;
	int recvbuflen;
	string recvbuf_copy;
	std::string hostAddr, domainip;
	SOCKET RemoteSocket;
	struct sockaddr_in remoteAddr;
	SSL *client_ssl;
	string default_certificate;
	string server_certificate;
	SSL_CTX *client_ctx = clear_method((SSL_METHOD *)SSLv23_client_method());
	SSL_CTX *server_ctx = clear_method((SSL_METHOD *)SSLv23_method());//SSL_CTX()
	server_certificate += PATH;
	default_certificate += PATH;
	default_certificate += "default.pem";
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
	if ((recvbuflen = recv(Client, buf, BUFFER, 0)) > 0)
	{
		if (strstr(buf, "CONNECT") != NULL)
		{
			send(Client, "HTTP/1.0 200 Connection established\r\n\r\n", strlen("HTTP/1.0 200 Connection established\r\n\r\n"), 0);
		}
	}
	InitializeCriticalSection(&cs);
	while (true)
	{
		
		if ((server_ssl = SSL_new(server_ctx)) == NULL)
		{
			std::cout << "SSL NULL" << std::endl;
		}
		if (!SSL_CTX_set_tlsext_servername_callback(server_ctx, servernamecallback))
		{
			cout << "ssl_ctx_set_tlsext_servername_callback return false" << endl;
		}

		if (!SSL_CTX_set_tlsext_servername_arg(server_ctx, NULL))
		{
			cout << "ssl_ctx_set_tlsext_servername_arg return false" << endl;

		}
		SSL_set_fd(server_ssl, Client);
		if (SSL_accept(server_ssl) == -1)
		{
			cout << "accept Error" << endl;
		}
		cout << "ssl_accept success" << endl;
		hostAddr = SSL_get_servername(server_ssl, TLSEXT_NAMETYPE_host_name);
		cout << "접속 성공" << endl;
		cout << "호스트 :" << hostAddr;

		if (hostAddr == "")
		{
			
		load_certificate(client_ctx, default_certificate, default_certificate);
		}
		server_certificate += hostAddr;
		server_certificate += ".pem";
		domainip = URLToAddrStr(hostAddr);
		if (domainip == "")
		{
			return;
		}
		






		if ((RemoteSocket = socket(PF_INET, SOCK_STREAM, 0)) == INVALID_SOCKET)
		{
			errorHandle("ERROR : Create a Socket for conneting to server\n", NULL);
		}
		std::cout << "remote 소켓생성 완료" << endl;
		remoteAddr = initAddr(port, domainip); //포트와 도메인 소켓에 넣기 
		if (connect(RemoteSocket, (struct sockaddr*) &remoteAddr, sizeof(remoteAddr)) == SOCKET_ERROR)
		{
			errorHandle("Connect Socket err", RemoteSocket);
			continue;
		}
		if ((client_ssl = SSL_new(client_ctx)) == NULL)
		{
			cout << "ssl is empty" << endl;
		}
		cout << "클라이언트 호스트 : " << hostAddr;
		SSL_set_connect_state(client_ssl); //자동으로 SSL_CONNECT가 가능하도록 설정해주는 함수
		SSL_set_fd(client_ssl, RemoteSocket);
		if (SSL_connect(client_ssl) == NULL)
		{
			cout << " ssl not connect" << endl;
			SSL_free(client_ssl);
			continue;
		}
		printf("SSL connection using %s\n", SSL_get_cipher(client_ssl));
		std::cout << "remote 연결" << endl;
		certificate(client_ssl, 1);

		std::thread(ssl_backward, server_ssl, client_ssl).detach(); //여기도 블락 걸림









		while ((recvbuflen = SSL_read(server_ssl, buf, BUFFER)) > 0)
		{
			cout << "Forward :" << recvbuflen << endl;
			recvbuf = (char *)calloc(recvbuflen, sizeof(char));
			memcpy(recvbuf, buf, recvbuflen);
			cout << "연결후 요청 패킷" << endl;
			cout << recvbuf << endl;
			













			
			std::cout << "웹서버로 보냄\n" << endl;
			if (SSL_write(client_ssl, recvbuf, recvbuflen) == SOCKET_ERROR)
			{
				printf("send to webserver failed.");
				break;
			}
			
			memset(buf, NULL, BUFFER);

		
		}
		//SSL_free(client_ssl);
		
		
		//closesocket(RemoteSocket);
	}
	DeleteCriticalSection(&cs);
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

