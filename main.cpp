
#include "lib.h"



#define MIN(a, b) (a < b? a : b)

//we only use one instance per run so we keep some globals, scdbg hooks expect this..
emu_env_w32* env = 0;
uc_engine *uc = 0;
uc_engine *mem = 0; 
emu_cpu *cpu;

run_time_options opts;
int ctrl_c_count=0;

extern void parse_opts(int argc, char* argv[] );
extern void interactive_command();

int __stdcall ctrl_c_handler(DWORD arg){
	if(arg==0){ //ctrl_c event
			opts.verbose = 3;             //break next instruction
			ctrl_c_count++;               //user hit ctrl c a couple times, 
			if(ctrl_c_count > 1) exit(0); //must want out for real.. (zeroed each step)
			return TRUE;
	}
	return FALSE;
}

int HookDetector(char* fxName){

	/*  typical api prolog 0-5, security apps will replace this with jmp xxxxxxxx
		which the hookers will detect, or sometimes just jump over always without checking..
		the jump without checking screws us up, so were compensating with this callback...
		7C801D7B   8BFF             MOV EDI,EDI
		7C801D7D   55               PUSH EBP
		7C801D7E   8BEC             MOV EBP,ESP
	*/

	//todo: wire in antispam?
	color_printf(myellow, "\tjmp %s+5 hook evasion code detected! trying to recover...\n", fxName);

	cpu->reg[esp] = cpu->reg[ebp];
	cpu->reg[ebp] = popd();
	return 1;
}

void set_hooks(struct emu_env_w32 *env){

	extern int32_t	__stdcall hook_GenericStub(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex);
	extern int32_t	__stdcall hook_GenericStub2String(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex);
	extern int32_t	__stdcall hook_shdocvw65(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex);
 
	#define GENERICHOOK(name) if(emu_env_w32_export_new_hook(env, #name, hook_GenericStub, NULL) < 0) printf("Failed to set generic Hook %s\n",#name);

	#define ADDHOOK(name) \
		extern int32_t	__stdcall hook_##name(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex);\
		if(emu_env_w32_export_new_hook(env, #name, hook_##name, NULL) < 0) printf("Failed to setHook %s\n",#name);

	#define HOOKBOTH(name) \
		extern int32_t	__stdcall hook_##name(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex);\
		if(emu_env_w32_export_new_hook(env, #name"A", hook_##name, NULL) < 0) printf("Failed to setHook %s\n",#name"A");\
		if(emu_env_w32_export_new_hook(env, #name"W", hook_##name, NULL) < 0) printf("Failed to setHook %s\n",#name"W");

	//following support both Ascii and Wide api
	HOOKBOTH(PathFileExists);
	HOOKBOTH(LoadLibrary);
	HOOKBOTH(GetTempPath);
    HOOKBOTH(GetTempFileName);
    HOOKBOTH(URLDownloadToFile);
	HOOKBOTH(MoveFile);
    HOOKBOTH(GetModuleFileName);
	HOOKBOTH(URLDownloadToCacheFile);
	HOOKBOTH(CreateProcessInternal);
	HOOKBOTH(CryptAcquireContext);
	HOOKBOTH(OpenService);
	HOOKBOTH(RegOpenKeyEx);
	HOOKBOTH(OpenSCManager);
	HOOKBOTH(CreateFile);
	HOOKBOTH(InternetSetOption);
	HOOKBOTH(CreateProcess);
	HOOKBOTH(GetStartupInfo);
	HOOKBOTH(MoveFileWithProgress);
    HOOKBOTH(GetVersionEx);
	HOOKBOTH(CreateMutex);
	HOOKBOTH(OpenMutex);
	HOOKBOTH(RegDeleteKey);
    HOOKBOTH(GetModuleHandle);
	HOOKBOTH(DeleteFile);
	HOOKBOTH(GetFileAttributes);
    HOOKBOTH(CreateNamedPipe);

	//these are up here because this declares the extern so we can break macro pattern in manual hooking below..
	ADDHOOK(ExitProcess);
	ADDHOOK(memset);
	ADDHOOK(memcpy);
	ADDHOOK(GetFileSize);
	ADDHOOK(GlobalAlloc);
	ADDHOOK(strstr);
	ADDHOOK(strtoul);
    ADDHOOK(lstrcatA);
	ADDHOOK(strrchr);
	ADDHOOK(VirtualQuery);
	ADDHOOK(strcmp);
	ADDHOOK(Process32First);
	ADDHOOK(_stricmp);
    ADDHOOK(GetKeyState);
	ADDHOOK(memchr);
	ADDHOOK(memcmp);
    ADDHOOK(strcpy);

	//these dont follow the macro pattern..mostly redirects/multitasks
	emu_env_w32_export_new_hook(env, "LoadLibraryExA",  hook_LoadLibrary, NULL);
	emu_env_w32_export_new_hook(env, "ExitThread", hook_ExitProcess, NULL);
	emu_env_w32_export_new_hook(env, "GetFileSizeEx", hook_GetFileSize, NULL);
	emu_env_w32_export_new_hook(env, "LocalAlloc", hook_GlobalAlloc, NULL);
	emu_env_w32_export_new_hook(env, "strcat", hook_lstrcatA, NULL);
    emu_env_w32_export_new_hook(env, "RtlMoveMemory", hook_memcpy, NULL); //kernel32. found first...
    emu_env_w32_export_new_hook(env, "CopyMemory", hook_memcpy, NULL);
	emu_env_w32_export_new_hook(env, "VirtualQueryEx", hook_VirtualQuery, NULL);
    emu_env_w32_export_new_hook(env, "strcmp", hook__stricmp, NULL);     //ntdll hit first
	emu_env_w32_export_new_hook(env, "Process32Next", hook_Process32First, NULL);
	emu_env_w32_export_new_hook(env, "GetAsyncKeyState", hook_GetKeyState, NULL);

	//-----handled by the generic stub 2 string
	emu_env_w32_export_new_hook(env, "InternetOpenA", hook_GenericStub2String, NULL);
	emu_env_w32_export_new_hook(env, "InternetOpenUrlA", hook_GenericStub2String, NULL);
	emu_env_w32_export_new_hook(env, "SHRegGetBoolUSValueA", hook_GenericStub2String, NULL);

	//-----by ordinal
	emu_env_w32_export_new_hook_ordinal(env, "shdocvw", 0x65,  hook_shdocvw65);
	emu_env_w32_export_new_hook_ordinal(env, "msvcrt", 0x02E1, hook_memset);   //have to hook this one by ordinal cause it finds ntdll.memset first
	emu_env_w32_export_new_hook_ordinal(env, "msvcrt", 0x030d, hook_strstr);   //have to hook this one by ordinal cause it finds ntdll.strstr first
	emu_env_w32_export_new_hook_ordinal(env, "msvcrt", 0x0311, hook_strtoul);  //have to hook this one by ordinal cause it finds ntdll.strtoul first
	emu_env_w32_export_new_hook_ordinal(env, "msvcrt", 0x02DF, hook_memcpy);   //have to hook this one by ordinal cause it finds ntdll  first
	emu_env_w32_export_new_hook_ordinal(env, "msvcrt", 0x02FE, hook_lstrcatA); //have to hook this one by ordinal cause it finds ntdll  first
	emu_env_w32_export_new_hook_ordinal(env, "msvcrt", 0x030b, hook_strrchr);  //have to hook this one by ordinal cause it finds ntdll  first
    emu_env_w32_export_new_hook_ordinal(env, "msvcrt", 0x0300, hook__stricmp); //have to hook this one by ordinal cause it finds ntdll  first
	emu_env_w32_export_new_hook_ordinal(env, "msvcrt", 0x02dd, hook_memchr);   //have to hook this one by ordinal cause it finds ntdll  first
	emu_env_w32_export_new_hook_ordinal(env, "msvcrt", 0x02de, hook_memcmp);   //have to hook this one by ordinal cause it finds ntdll  first
	emu_env_w32_export_new_hook_ordinal(env, "msvcrt", 0x0302, hook_strcpy);   //have to hook this one by ordinal cause it finds ntdll  first

	emu_env_w32_export_new_hook_ordinal(env, "ntdll", 0x02C7, hook_memcpy);    //RtlMoveMemory found in k32 first...

	//-----handled by the generic stub
	GENERICHOOK(ZwTerminateProcess);
	GENERICHOOK(ZwTerminateThread);
	GENERICHOOK(TerminateThread);
	GENERICHOOK(FreeLibrary);
	GENERICHOOK(GlobalFree);
	GENERICHOOK(GetCurrentProcess);
	GENERICHOOK(TerminateProcess);
	GENERICHOOK(CreateThread);
	GENERICHOOK(GetSystemTime);
	GENERICHOOK(SetSystemTime);
	GENERICHOOK(RtlDestroyEnvironment);
	GENERICHOOK(RevertToSelf);
	GENERICHOOK(RtlExitUserThread);
	GENERICHOOK(FlushViewOfFile);
    GENERICHOOK(UnmapViewOfFile);
	GENERICHOOK(FindClose);
	GENERICHOOK(InternetCloseHandle);
	GENERICHOOK(GetCurrentThread);
	GENERICHOOK(CloseServiceHandle);
	GENERICHOOK(DeleteService);
	GENERICHOOK(AdjustTokenPrivileges)

	ADDHOOK(MessageBoxA);
	ADDHOOK(ShellExecuteA);
	ADDHOOK(SHGetSpecialFolderPathA);
	ADDHOOK(MapViewOfFile);
	ADDHOOK(system);
	ADDHOOK(VirtualAlloc);
	ADDHOOK(VirtualProtectEx);
	ADDHOOK(SetFilePointer);
	ADDHOOK(ReadFile);
	ADDHOOK(DialogBoxIndirectParamA);
	ADDHOOK(ZwQueryVirtualMemory);
	ADDHOOK(GetEnvironmentVariableA);
	ADDHOOK(VirtualAllocEx);
	ADDHOOK(WriteProcessMemory);
	ADDHOOK(CreateRemoteThread);
	ADDHOOK(MultiByteToWideChar);
	ADDHOOK(_execv);
	ADDHOOK(fclose);
	ADDHOOK(fopen);
	ADDHOOK(fwrite);
	ADDHOOK(_lcreat);
	ADDHOOK(_lclose);
	ADDHOOK(_lwrite);
	ADDHOOK(_hwrite);
	ADDHOOK(GetTickCount);
	ADDHOOK(WinExec);
	ADDHOOK(Sleep);
	ADDHOOK(CloseHandle);
	ADDHOOK(GetVersion);
	ADDHOOK(GetProcAddress);
	ADDHOOK(GetSystemDirectoryA);
	ADDHOOK(malloc);
	ADDHOOK(SetUnhandledExceptionFilter);
	ADDHOOK(WaitForSingleObject);
	ADDHOOK(WriteFile);
	ADDHOOK(VirtualProtect);
	ADDHOOK(bind);
	ADDHOOK(accept);
	ADDHOOK(bind);
	ADDHOOK(closesocket);
	ADDHOOK(connect);
	ADDHOOK(listen);
	ADDHOOK(recv);
	ADDHOOK(send);
	ADDHOOK(sendto);
	ADDHOOK(socket);
	ADDHOOK(WSASocketA);
	ADDHOOK(WSAStartup);
	ADDHOOK(CreateFileMappingA);
	ADDHOOK(WideCharToMultiByte);
	ADDHOOK(GetLogicalDriveStringsA);
	ADDHOOK(FindWindowA);
	ADDHOOK(DeleteUrlCacheEntryA);
	ADDHOOK(FindFirstFileA);
	ADDHOOK(GetUrlCacheEntryInfoA);
	ADDHOOK(CopyFileA);
	ADDHOOK(EnumWindows);
	ADDHOOK(GetClassNameA);
	ADDHOOK(fread);
	ADDHOOK(IsBadReadPtr);
	ADDHOOK(GetCommandLineA);
	ADDHOOK(SHGetFolderPathA);
	ADDHOOK(CryptCreateHash);
	ADDHOOK(CryptHashData);
	ADDHOOK(CryptGetHashParam);
	ADDHOOK(CryptDestroyHash);
	ADDHOOK(CryptReleaseContext);
	ADDHOOK(InternetConnectA);
	ADDHOOK(HttpOpenRequestA);
	ADDHOOK(HttpSendRequestA);
	ADDHOOK(InternetReadFile);
	ADDHOOK(ControlService);
	ADDHOOK(QueryDosDeviceA);
	ADDHOOK(SHDeleteKeyA);
	ADDHOOK(CreateDirectoryA);
	ADDHOOK(SetCurrentDirectoryA);
	ADDHOOK(GetWindowThreadProcessId);
	ADDHOOK(OpenProcess);
	ADDHOOK(ExpandEnvironmentStringsA);
	ADDHOOK(lstrlenA);
	ADDHOOK(lstrcmpiA);
	ADDHOOK(lstrcpyA);
	ADDHOOK(OpenEventA);
	ADDHOOK(CreateEventA);
	ADDHOOK(GetThreadContext);
	ADDHOOK(SetThreadContext);
	ADDHOOK(ResumeThread);
	ADDHOOK(GetMappedFileNameA);
    ADDHOOK(ZwUnmapViewOfSection);
	ADDHOOK(SetEndOfFile);
	ADDHOOK(LookupPrivilegeValueA);
	ADDHOOK(OpenProcessToken);
	ADDHOOK(EnumProcesses);
	ADDHOOK(GetModuleBaseNameA);
	ADDHOOK(HttpQueryInfoA);
	ADDHOOK(StrToIntA);
	ADDHOOK(gethostbyname);
	ADDHOOK(ZwQueryInformationFile);
	ADDHOOK(ZwSetInformationProcess);
	ADDHOOK(fprintf);
	ADDHOOK(exit);
	ADDHOOK(GetLocalTime);
	ADDHOOK(ExitWindowsEx);
	ADDHOOK(SetFileAttributesA);
	ADDHOOK(GetLastError);
	ADDHOOK(IsDebuggerPresent);
	ADDHOOK(ZwQueryInformationProcess);
	ADDHOOK(OpenFileMappingA);
	ADDHOOK(time);
	ADDHOOK(srand);
	ADDHOOK(rand);
	ADDHOOK(inet_addr);
	ADDHOOK(wsprintfA);
    ADDHOOK(RtlDecompressBuffer);
	ADDHOOK(RtlZeroMemory);
	ADDHOOK(swprintf);
	ADDHOOK(RtlDosPathNameToNtPathName_U);
	ADDHOOK(ZwOpenFile);
	ADDHOOK(fseek);
	ADDHOOK(gethostname);
	ADDHOOK(SendARP);
	ADDHOOK(ZwCreateFile); //not interactive
	ADDHOOK(GetCurrentProcessId);
	ADDHOOK(GetCurrentThreadId);
	ADDHOOK(FreeLibraryAndExitThread);
	ADDHOOK(CreateToolhelp32Snapshot);
	ADDHOOK(Thread32First);
	ADDHOOK(Thread32Next);
	ADDHOOK(OpenThread);
	ADDHOOK(SuspendThread);
	ADDHOOK(FreeLibrary);
	ADDHOOK(ZwAllocateVirtualMemory);
	ADDHOOK(DeviceIoControl);
	ADDHOOK(GetSystemTimeAsFileTime);
	ADDHOOK(VirtualFree);
	ADDHOOK(RtlGetLastWin32Error);
	ADDHOOK(ZwSetContextThread);
	ADDHOOK(WinHttpCrackUrl);
	ADDHOOK(WinHttpOpen);
	ADDHOOK(WinHttpGetIEProxyConfigForCurrentUser);
	ADDHOOK(WinHttpConnect);
	ADDHOOK(WinHttpOpenRequest);
	ADDHOOK(WinHttpSendRequest);
	ADDHOOK(WinHttpReceiveResponse);
	ADDHOOK(WinHttpQueryHeaders);
	ADDHOOK(WinHttpCloseHandle);
	ADDHOOK(lstrcatW);
	ADDHOOK(IsWow64Process);
	ADDHOOK(GetDesktopWindow);
	ADDHOOK(InternetErrorDlg);
	ADDHOOK(GetProcessAffinityMask);
	ADDHOOK(HeapCreate);
	ADDHOOK(setsockopt);
	ADDHOOK(WSAAccept);
	ADDHOOK(GetSystemInfo);
	ADDHOOK(ConnectNamedPipe);

}


void debugCPU(bool showdisasm){

	int i=0;
	if (opts.verbose == 0) return;

	//verbose 1= offset opcodes disasm step count every 5th hit
	//        2= adds register and flag dump
    //        3 = debug shell

    if(showdisasm){
        uint32_t m_eip = emu_cpu_eip_get(uc);
    	disasm_addr(uc, m_eip);
    }

	if (opts.verbose < 2) return;
    dumpRegisters();
	
	//if(opts.verbose >= 3) 
		//show_stack();

	interactive_command();

	return;

}


static void hook_code(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
    int r_eip;
    int i;

    uc_reg_read(uc, UC_X86_REG_EIP, &r_eip);

    if(opts.steps == 0){
        uc_emu_stop(uc);
        return;
    }

    if(opts.steps != -1 && opts.cur_step > opts.steps){
        printf("reached max step count stopping\n");
        uc_emu_stop(uc);
        return;
    }

    if(cpu->eip != 0){
		for(i=0; i < 10; i++){
			if(cpu->eip == opts.bpx[i]){
				opts.verbose = 3;
				color_printf(myellow, "\tBreakpoint %d hit at: %x\n", i, cpu->eip);
				break;
			}
		}
	}

    if( opts.cur_step == opts.log_after_step && opts.log_after_step > 0 )
	{
        if(opts.verbosity_after==0) opts.verbosity_after = 1;
		opts.verbose = opts.verbosity_after;
		opts.log_after_step = 0;
		opts.log_after_va = 0;
	}


	debugCPU(true);

	struct emu_env_w32_dll_export *ex = NULL;
	ex = emu_env_w32_eip_check(env); //will execute the api hook if one is set..

	if ( ex != NULL) 
	{				
		if ( ex->fnhook == NULL )
		{
			if( strlen(ex->fnname) == 0)
				printf("%x\tunhooked call to ordinal %s.0x%x\tstep=%d\n", previous_eip , dllFromAddress(r_eip), ex->ordinal, opts.cur_step );
			else
				printf("%x\tunhooked call to %s.%s\tstep=%d\n", previous_eip, dllFromAddress(r_eip), ex->fnname, opts.cur_step );
			uc_emu_stop(uc);
		}
	}else{
		previous_eip = r_eip;
	}

	logEip(r_eip);
	opts.cur_step++;

}

// callback for tracing memory access (READ or WRITE)
static bool hook_mem_invalid(uc_engine *uc, uc_mem_type type, uint64_t address, int size, int64_t value, void *user_data)
{
	
	nl();
	opts.verbose = 4;
	
    switch(type) {
        default:
			  printf(">>> hook_mem_invalid %d at 0x%llX, data size = %u, data value = 0x%llX\n", type, address, size, value);
              break;
			  // return false to indicate we want to stop emulation
            
		case UC_MEM_READ_UNMAPPED:
			   printf(">>> Missing memory is being READ at 0x%llX, data size = %u, data value = 0x%llX\n", address, size, value);
			   break;

        case UC_MEM_WRITE_UNMAPPED:
               printf(">>> Missing memory is being WRITE at 0x%llX, data size = %u, data value = 0x%llX\n", address, size, value);
               break;             
				 // map this memory in with 2MB in size
                 //uc_mem_map(uc, 0xaaaa0000, 2 * 1024*1024, UC_PROT_ALL);
                 // return true to indicate we want to continue
                 //return true;
    }

	debugCPU(true);
	return false;
}





static void run_sc(void)
{
    uc_err err;
    uc_hook trace1;

    uint32_t stack = 0x120000;
    uint32_t stack_sz = 0x10000;
    uc_mem_map(uc, stack, stack_sz, UC_PROT_ALL);
	emu_reg32_write(uc, esp, stack + stack_sz);
 
    if (emu_memory_write_block(uc, opts.baseAddress, opts.scode, opts.size)) {
        printf("Failed to write shellcode to memory\n");
        return;
    }
    
    // tracing all instructions by having @begin > @end
    uc_hook_add(uc, &trace1, UC_HOOK_CODE, hook_code, NULL, -1, 0);

    // intercept invalid memory events
    uc_hook_add(uc, &trace1, UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED, hook_mem_invalid, NULL, 1, 0);

    color_printf(myellow, "\nStarting shellcode\n\n");

    err = uc_emu_start(uc, opts.baseAddress,  opts.baseAddress + opts.size, 0, 0);

    if(err) {
        color_printf(mred, "Error %u: %s\n", err, uc_strerror(err));
		if(opts.verbose < opts.verbosity_onerr)	opts.verbose = opts.verbosity_onerr; 
		if(opts.verbose < 2) opts.verbose = 2; //always show disasm and regs on error now..
		debugCPU(true);
    }

	printf("\nemulation complete %x steps last eip=%x\n", opts.cur_step, emu_cpu_eip_get(uc));

    if(opts.dump_mode && opts.file_mode){  // dump decoded buffer
		do_memdump();
	}


}

int main(int argc, char **argv, char **envp)
{

	unsigned int vMaj, vMin;

    memset(&opts,0,sizeof(struct run_time_options));

	nl();
	min_window_size();
	SetConsoleTitle("scdbg - http://sandsprite.com"); //so you only have to set quick edit mode once for this caption..
	SetConsoleCtrlHandler(ctrl_c_handler, TRUE); //http://msdn.microsoft.com/en-us/library/ms686016

	hCon = GetStdHandle( STD_INPUT_HANDLE );
	hConOut = GetStdHandle( STD_OUTPUT_HANDLE );
	setvbuf(stdout, NULL, _IONBF, 0); //autoflush - allows external apps to read cmdline output in realtime..

	DWORD old;
	GetConsoleMode(hCon, &old);
	old |= ENABLE_QUICK_EDIT_MODE | ENABLE_EXTENDED_FLAGS ; //always enable this and leave it this way..
	orgt = old;
	old &= ~ENABLE_LINE_INPUT;

	signal(SIGABRT,restore_terminal);
    signal(SIGTERM,restore_terminal);
	atexit(atexit_restore_terminal);

	if (!uc_dyn_load(NULL, 0)) {
        printf("Error dynamically loading unicorn.dll Failed to find:%s\n", lastDynLoadErr);	
	} 
	
	uc_version(&vMaj,&vMin);
	printf("loaded Unicorn emulator v%d.%d\n", vMaj,vMin);
	printf("building new libemu win32 env...\n");
    env = emu_env_w32_new();

    if(env==NULL){
        printf("failed\n");
        return 0;
    }
    
    uc = env->uc;
    mem = uc;
    cpu = emu_cpu_get(uc);
	
	//printf("setting api hooks...\n");
	set_hooks(env);
  	parse_opts(argc, argv); //this must happen AFTER emu_env_new for -bp apiname lookup

    loadsc();	
    
    if( opts.offset > opts.baseAddress ){
		color_printf(myellow, "/foff looks like a VirtualAddress adjusting to file offset...\n");
		opts.offset -= opts.baseAddress;
	}

    emu_env_w32_set_hookDetect_monitor((uint32_t)HookDetector);
   
    printf("Max Steps: %d\n", opts.steps);
	printf("Using base offset: 0x%x\n", opts.baseAddress);
	if(opts.verbose>0) printf("Verbosity: %i\n", opts.verbose);

	run_sc();
    //uc_close(env->uc);

    if( IsDebuggerPresent() ) {
		printf("Press any key to exit...\n");	
		getch();
	}

    return 0;
}
