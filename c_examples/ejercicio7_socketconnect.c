/*
 ejercicio7_socketconnect.c
 Programa básico: Crear socket y conectar usando socket/connect (llama a NtDeviceIoControlFile para networking).
 Compila con: cl ejercicio7_socketconnect.c ws2_32.lib
 Ejecuta: .\ejercicio7_socketconnect.exe
 Analiza con depuradores para ver syscalls de networking.
*/

#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>
#pragma comment(lib, "ws2_32.lib")

int main() {
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        printf("Error WSAStartup: %d\n", WSAGetLastError());
        return 1;
    }

    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) {
        printf("Error socket: %d\n", WSAGetLastError());
        WSACleanup();
        return 1;
    }

    struct sockaddr_in server;
    server.sin_addr.s_addr = inet_addr("127.0.0.1");
    server.sin_family = AF_INET;
    server.sin_port = htons(80);

    if (connect(sock, (struct sockaddr*)&server, sizeof(server)) == SOCKET_ERROR) {
        printf("Error connect: %d\n", WSAGetLastError());
    } else {
        printf("Conectado a localhost:80\n");
    }

    closesocket(sock);
    WSACleanup();
    return 0;
}