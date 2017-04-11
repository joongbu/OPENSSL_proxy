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
#include <fcntl.h>
#pragma comment (lib, "Ws2_32.lib")
#define BUFFER 70000 //tcp 패킷 최대 바이트 수
std::string getAddr(char *_data);
void checkArguments(int argc, char **argv);
std::string URLToAddrStr(std::string addr);
struct sockaddr_in initAddr(int port, std::string addr);
void initWSA();
void errorHandle(std::string msg, SOCKET s);
void forward(struct sockaddr_in serverAddr, SOCKET Client, SSL *server_ssl);
void open_socket(SOCKET &sock, struct sockaddr_in &sockaddr);
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
	SSL_CTX *server_ctx = clear_method((SSL_METHOD *)TLSv1_1_server_method());

	if (!server_ctx)
	{
		ERR_print_errors_fp(stderr);
		std::cout << "ctx error";
	}
	load_certificate(server_ctx, "C:/Program Files/SnoopSpy/certificate/default.pem", "C:/Program Files/SnoopSpy/certificate/default.pem");
	open_socket(Server, serverAddr); //소켓 생성 함수
	SSL *server_ssl;
	
	while (true)
	{

		if ((Client = accept(Server, NULL, NULL)) == INVALID_SOCKET)
		{
			printf("error : accept\n");
			continue;
		}

		server_ssl = SSL_new(server_ctx); //설정된 Contexxt를 이용하여 SSL 세션의 초기화 작업을 수행한다.
		SSL_set_fd(server_ssl, Client);
		certificate(server_ssl, 0);
		char buf[BUFFER];
		memset(buf, NULL, BUFFER);
		recv(Client, buf, BUFFER, 0);
		cout << buf << endl;
		if (server_ssl == NULL)
		{
			std::cout << "SSL NULL" << std::endl;
		}

		std::cout << "Connection" << std::endl;
		std::cout << "암호키 얻음 : " << SSL_get_cipher(server_ssl) << std::endl;
		std::thread(forward, serverAddr, Client, server_ssl).detach();

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

void ssl_backward(SSL *server_ssl, SSL *remote_ssl)
{
	char buf[BUFFER];
	char *remotebuf;
	int recvlen;
	while ((recvlen = SSL_read(remote_ssl, buf, BUFFER)) > 0)//타임아웃 걸기
	{
		std::cout << "수신완료" << endl;
		if (recvlen == SOCKET_ERROR)
		{
			std::cout << "error : ssl backward recv()" << endl;
			continue;
		}
		remotebuf = (char *)calloc(recvlen, sizeof(recvlen)); //recv 받은 바이트 만큼 저장
		memcpy(remotebuf, buf, recvlen);
		std::cout << "ssl클라이언트 => ssl웹으로 전송\n";
		std::cout << "=============================================" << endl;
		cout << "ssl 내용" << endl;
		cout << remotebuf << endl;
		if (SSL_write(server_ssl, remotebuf, recvlen) == SOCKET_ERROR)
		{
			printf("ssl packet send to client failed.");
			continue;
		}
	}
	std::cout << "클라이언트로 전송완료" << endl;
	std::cout << " 쓰레드 종료" << endl;
}
void forward(struct sockaddr_in serverAddr, SOCKET Client, SSL *server_ssl)
{
	int port = 443;
	char buf[BUFFER];
	char *recvbuf;
	int recvbuflen;
	std::string hostAddr, domainip;
	SOCKET RemoteSocket;
	struct sockaddr_in remoteAddr;
	SSL *client_ssl;
	int r;

	if ((r = SSL_accept(server_ssl)) == -1)
	{
		int err_SSL_get_error = SSL_get_error(server_ssl, r);
		int err_GetLastError = GetLastError();
		int err_WSAGetLastError = WSAGetLastError();
		int err_ERR_get_error = ERR_get_error();

		std::cout << "[DEBUG] SSL_accept() : Failed with return "
			<< r << std::endl;
		std::cout << "[DEBUG] SSL_get_error() returned : "
			<< err_SSL_get_error << std::endl;
		std::cout << "[DEBUG] Error string : "
			<< ERR_error_string(err_SSL_get_error, NULL)
			<< std::endl;
		std::cout << "[DEBUG] WSAGetLastError() returned : "
			<< err_WSAGetLastError << std::endl;
		std::cout << "[DEBUG] GetLastError() returned : "
			<< err_GetLastError << std::endl;
		std::cout << "[DEBUG] ERR_get_error() returned : "
			<< err_ERR_get_error << std::endl;
		std::cout << "[DEBUG] GetLastError() returned : "
			<< GetLastError << std::endl;
		std::cout << "+--------------------------------------------------+"
			<< std::endl;
		
		return;
	}

	while ((recvbuflen = SSL_read(server_ssl, buf, BUFFER)) > 0)
	{
		
		SSL_CTX *client_ctx = clear_method((SSL_METHOD *)SSLv23_client_method());
		if (client_ctx == NULL)
		{
			cout << "client ctx error";
			break;
		}
		load_certificate(client_ctx, "C:/Program Files/SnoopSpy/certificate/default.crt", "C:/Program Files/SnoopSpy/certificate/default.key");
		
		recvbuf = (char *)calloc(recvbuflen, sizeof(char));
		memcpy(recvbuf, buf, recvbuflen);
		hostAddr = getAddr(recvbuf); //여기서 443 포트 번호 확인해야한다.
		std::cout << "site : " << hostAddr << endl;
		std::cout << "=============================================" << endl;
		std::cout << "클라이언트 => 프록시으로 전송 \n";
		std::cout << "=============================================" << endl;
		std::cout << "포트번호 :" << port << endl;
		std::cout << recvbuf << endl;
		
		if (hostAddr == "")
		{
			printf("Empty Host Address..\n");
			break;
		}
		else
			domainip = URLToAddrStr(hostAddr);

		if (domainip == "")
		{
			break;
		}

		remoteAddr = initAddr(port, domainip); //포트와 도메인 소켓에 넣기
		if ((RemoteSocket = socket(PF_INET, SOCK_STREAM, 0)) == INVALID_SOCKET)
		{
			errorHandle("ERROR : Create a Socket for conneting to server\n", NULL);
		}
		std::cout << "remote 소켓생성 완료" << endl;
		if (connect(RemoteSocket, (struct sockaddr*) &remoteAddr, sizeof(remoteAddr)) == SOCKET_ERROR)
		{
			std::cout << "연결실패" << endl;
			break;
		}
		if ((client_ssl = SSL_new(client_ctx)) == NULL)
		{
			cout << "ssl is empty" << endl;
			break;
		}//자원 할당
		
		SSL_set_fd(client_ssl, RemoteSocket);
		if (SSL_connect(client_ssl) == NULL)
		{
			cout << " ssl not connect" << endl;
			break;
		}
		printf("SSL connection using %s\n", SSL_get_cipher(client_ssl));
		std::cout << "remote 연결" << endl;
		certificate(client_ssl, 1);
		cout << "Success server certificate" << endl;
		//다른 쓰레드 function
		std::thread(ssl_backward, server_ssl, client_ssl).detach();
		if (SSL_write(client_ssl, recvbuf, recvbuflen) == SOCKET_ERROR) //remote
		{
			printf("send to webserver failed.");
			continue;
		}
		std::cout << "프록시로 보냄\n" << endl;
	}
	memset(buf, NULL, BUFFER); //NULL 초기화
	//closesocket(Client);
	//SSL_free(server_ssl);
	
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

