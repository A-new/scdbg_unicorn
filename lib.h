#ifndef lib_H
#define lib_H

#include <stdint.h>
#include <stdio.h>
#include <hash_map>
#include <string>
#include <stdarg.h>
#include <errno.h>
#include <string.h>
#include <ctype.h>
#include <windows.h>
#include <conio.h>
#include <signal.h>
#include <io.h>
#include <algorithm>
#include <stdlib.h>

#include <Shlobj.h>
#include <time.h>
#include <ctype.h>
#include <winsock.h>
#include <wininet.h>
#include <Shlobj.h>
#include <TlHelp32.h>
//#include <Winhttp.h>


#include "./Unicorn/unicorn_dynload.h"
#include "./libdasm/libdasm.h"
#include "./libemu/emu_shim.h"
#include "./libemu/emu_env_w32.h"
#include "./libemu/emu_env_w32_dll.h"
#include "./libemu/emu_env_w32_dll_export.h"
#include "./libemu/emu_string.h"

enum colors{ mwhite=15, mgreen=10, mred=12, myellow=14, mblue=9, mpurple=5, mgrey=7, mdkgrey=8 };

struct run_time_options
{
	int opts_parsed;
	int cur_step;
	int verbose;
	uint32_t steps;
	unsigned char *scode;
	uint32_t size;        //shellcode size
	uint32_t offset;      //start at offset x within shellcode (usually 0)
	uint32_t baseAddress; //where in memory shellcode is based at
	bool file_mode;
	bool getpc_mode;
	char sc_file[500];
	bool dump_mode;
	int interactive_hooks;
	int  log_after_va;
	int  log_after_step;
	int  verbosity_after;
	int  verbosity_onerr;
	bool exec_till_ret;
	int  time_delay;
	bool show_hexdumps;
	char* break_at_instr;
	bool  mem_monitor;
	bool  mem_monitor_dlls;
	bool  no_color;
	int   hexdump_file;
	int   disasm_mode;
	uint32_t step_over_bp;
	char* fopen_fpath;
	uint32_t fopen_fsize;
	HANDLE h_fopen;
	int	  adjust_getfsize;
	bool  report;
	bool  break0;
	uint32_t break_above;
	char* patch_file;
	char* scan_dir;
	bool  CreateFileOverride;
	char* cmdline;
	bool findApi;
	bool sigScan;
	bool automationRun;
	bool noseh;
	char* temp_dir;
	int   min_steps;
	bool  norw;
	bool  rop;
	bool  nofile;
    bool  bSwap;
	bool  eSwap;
	char* convert_outPath;
	HWND IDASrvrHwnd;
	uint32_t IDAImgBase;
	uint32_t bpx[10];
	//loadlib_override llo[10];
    uint32_t xorVal;
    uint32_t padding;
    bool hexInMode;

	struct{
		char *host;
		int port;
	}override;

};

struct m_allocs{
	uint32_t base;
	uint32_t size;
};

typedef struct{
    int dwFlag;
    int cbSize;
    int lpData;
} cpyData;

extern uint32_t MAX_ALLOC;
extern int nextDropIndex;
extern int nextFhandle;
extern DWORD orgt;
extern HANDLE hCon;
extern HANDLE hConOut;
extern uint32_t FS_SEGMENT_DEFAULT_OFFSET;
extern run_time_options opts;
extern int r32_t[9];
extern char *regm[];
extern uint32_t previous_eip;
extern uint32_t eip_log[10];
extern const int eip_log_sz;
extern int malloc_cnt;
extern struct m_allocs mallocs[];
extern uint32_t last_good_eip;
extern uint32_t previous_eip;

extern emu_env_w32* env;
extern uc_engine *uc;
extern uc_engine *mem;
extern emu_cpu *cpu;

void min_window_size(void);
void add_malloc(uint32_t base, uint32_t size);
bool allocExists(uint32_t base);
uint32_t allocSize(uint32_t base);
void dumpRegisters(void);
void show_help(void);
void m_exit(int arg);
void loadsc(void);
void do_memdump(void);
uint32_t popd(void);
char* dllFromAddress(uint32_t addr);
int fulllookupAddress(int eip, char* buf255);
char* getDumpPath(char* extension);
int get_fhandle(void);
int file_length(FILE *f);
char* FileNameFromPath(char* path);
char* GetParentFolder(char* path);
bool FolderExists(char* folder);
bool FileExists(LPCTSTR szPath);
uint32_t stripChars(unsigned char* buf_in, int *output, uint32_t sz, char* chars);
char* strlower(char* input);
int HexToBin(char* input, int* output);
void nl(void);
bool isDllMemAddress(uint32_t eip);
int disasm_addr(uc_engine *uc, int va, int justDisasm=0);
void real_hexdump(unsigned char* str, int len, int offset, bool hexonly);
void hexdump(unsigned char* str, int len);
void end_color(void);
void restore_terminal(int arg);
void atexit_restore_terminal(void);
void start_color(enum colors c);
void color_printf(colors c, const char *format, ...);
char* SafeMalloc(uint32_t size);
char* SafeTempFile(void);
uint32_t symbol2addr(char* symbol);
void symbol_lookup(char* symbol);
int findFreeBPXSlot(void);
void showEipLog(void);
void logEip(uint32_t eip);
void set_ret(uint32_t val);
bool isWapi(char*fxName);
struct emu_string* popstring(void);
struct emu_string* popwstring(void);

void IDASync(uint32_t eip);
void IDAConnect(void);
HWND IDASrvrHWND(void);
void IDASetComment(uint32_t eip, char* cmt);
int IDASendTextMessage(HWND hwnd, char *buf);
uint32_t get_instr_length(uint32_t va);
int disasm_addr_simple(int va);
int validated_lookup(uint32_t eip);
void xorBuf(unsigned char* buf, uint32_t sz, char* id);
void byteSwap(unsigned char* buf, uint32_t sz, char* id);
void endianSwap(unsigned char* buf, uint32_t sz, char* id);
void disasm_block(int offset, int size);

#endif