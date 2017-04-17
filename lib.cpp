
#include <stdint.h>
#include <stdio.h>
#include <conio.h>

#include "lib.h"
#include "./Unicorn/unicorn_dynload.h"
#include "./libdasm/libdasm.h"
#include "./libemu/emu_shim.h"
#include "./libemu/emu_env_w32.h"
#include "./libemu/emu_env_w32_dll.h"
#include "./libemu/emu_env_w32_dll_export.h"
#include "./libemu/emu_string.h"

DWORD orgt=0;
HANDLE hCon = 0;
HANDLE hConOut = 0;
uint32_t MAX_ALLOC  = 0x1000000;
int nextDropIndex=0;
int nextFhandle = 0;
uint32_t previous_eip=0;
uint32_t eip_log[10] = {0,0,0,0,0,0,0,0,0,0};
const int eip_log_sz = 10;
uint32_t FS_SEGMENT_DEFAULT_OFFSET = 0x7ffdf000;
char *regm[] = {"eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi", "eip"};
UINT IDA_QUICKCALL_MESSAGE;
int malloc_cnt=0;
struct m_allocs mallocs[21];
uint32_t last_good_eip=0;

void m_exit(int arg){
	if( IsDebuggerPresent() ) {
		printf("Press any key to exit...\n");	
		getch();
	}
	exit(arg);
}

void dumpRegisters(void){
	for(int i=0;i<9;i++){
		printf("%s=%-8x  ", regm[i], emu_reg32_read(uc,(emu_reg32)i) );
		if(i==3)printf("\n");
	}
	//dumpFlags(emu_cpu_get(e));
	printf("\n");
}

uint32_t get_instr_length(uint32_t va){
	char disasm[200];
	return emu_disasm_addr(uc, va, disasm);  
}

int validated_lookup(uint32_t eip){
	char tmp[256];
	if(!isDllMemAddress(eip) ) return 0;
	return fulllookupAddress(eip, &tmp[0]);
}

int disasm_addr_simple(int va){
	char disasm[200];
	int len=0;
	len = emu_disasm_addr(uc, va, disasm);
	start_color(mgreen);
	printf("%x   %s\n", va, disasm);
	end_color();
	return len;
}

void add_malloc(uint32_t base, uint32_t size){
	if( malloc_cnt > 20 ) return;
//	if(opts.report) emu_memory_add_monitor_range(0x66, base, base + size); //catch instructions which write to it
	mallocs[malloc_cnt].base = base;
	mallocs[malloc_cnt].size = size;
	malloc_cnt++;
}

bool allocExists(uint32_t base){
	for(int i=0; i<=20; i++){
		if(mallocs[i].base == base) return true;
	}
	return false;
}

uint32_t allocSize(uint32_t base){
	for(int i=0; i<=20; i++){
		if(mallocs[i].base == base) return mallocs[i].size;
	}
	return 0;
}

uint32_t popd(void){
	uint32_t x=0;
	uint32_t r_esp = emu_reg32_read(uc, esp);
	if( emu_memory_read_dword(uc, r_esp, &x) == -1){
		printf("Failed to read stack memory at 0x%x", r_esp);
		exit(0);
	}
	emu_reg32_write(uc, esp, r_esp+4); 
	return x;
}

void set_ret(uint32_t val){
		emu_reg32_write(uc, eax, val); 
} 



bool isWapi(char*fxName){
	int x = strlen(fxName)-1;
	return fxName[x] == 'W' ? true : false;
}

struct emu_string* popstring(void){
	uint32_t addr = popd();
	struct emu_string *str = emu_string_new();
	emu_memory_read_string(uc, addr, str, 1256);
	return str;
}

struct emu_string* popwstring(void){
	uint32_t addr = popd();
	struct emu_string *str = emu_string_new();
	emu_memory_read_wide_string(uc, addr, str, 1256);
	return str;
}

int get_fhandle(void){
	nextFhandle+=4;
	return nextFhandle;
}

int file_length(FILE *f)
{
	int pos;
	int end;

	pos = ftell (f);
	fseek (f, 0, SEEK_END);
	end = ftell (f);
	fseek (f, pos, SEEK_SET);

	return end;
}

char* FileNameFromPath(char* path){
	if(path==NULL || strlen(path)==0) return strdup("");
	unsigned int x = strlen(path);
	while(x > 0){
		if( path[x-1] == '\\') break;
		x--;
	}
	int sz = strlen(path) - x;
	char* tmp = (char*)malloc(sz+2);
	memset(tmp,0,sz+2);
	for(int i=0; i < sz; i++){
		tmp[i] = path[x+i];
	}
	return tmp;
}

char* GetParentFolder(char* path){
	if(path==NULL || strlen(path)==0) return strdup("");
	unsigned int x = strlen(path);
	while(x > 0){
		if( path[x-1] == '\\') break;
		x--;
	}
	char* tmp = strdup(path);
	tmp[x]=0; //were not modifying parent string, just our copy..
	return tmp;
}

bool FileExists(LPCTSTR szPath)
{
  DWORD dwAttrib = GetFileAttributes(szPath);
  bool rv = (dwAttrib != INVALID_FILE_ATTRIBUTES && !(dwAttrib & FILE_ATTRIBUTE_DIRECTORY)) ? true : false;
  return rv;
}

bool FolderExists(char* folder)
{
	DWORD rv = GetFileAttributes(folder);
	if( rv == INVALID_FILE_ATTRIBUTES) return false;
	if( !(rv & FILE_ATTRIBUTE_DIRECTORY) ) return false;
	return true;
}

char* SafeMalloc(uint32_t size){
	char* buf = 0;
	if(size > 0 && size <= MAX_ALLOC) buf = (char*)malloc(size);
	if( (int)buf == 0){
		printf("SafeMalloc Failed/refused to allocate 0x%x bytes exiting...",size);
		exit(0);
	}
	memset(buf,0,size);
	return buf;
}


char* getDumpPath(char* extension){
	
	char* tmp_path;
	char* fname;
	 
	tmp_path = SafeMalloc(strlen(opts.sc_file) + 50);
	strcpy(tmp_path, opts.sc_file);
	
	int x = strlen(tmp_path);
	while(x > 0){ //ida only uses up to first . in idb name so strip all other extensions from base name.
		if(tmp_path[x] == '.') tmp_path[x] = 0; //'_';
		if(tmp_path[x] == '\\' || tmp_path[x] == '/') break;
		x--;
	}
	sprintf(tmp_path,"%s.%s",tmp_path,extension);

	return tmp_path;
}

//now by default drops files to the shellcode parent dir unless overridden w -temp
char* SafeTempFile(void){ 
	char  ext[20];
	if(nextDropIndex > 100){
		//printf("To many temp files switching to tempname...\n");
		strncat((char*)ext,tmpnam(NULL),19);
	}else{
		sprintf((char*)ext, "drop_%d", nextDropIndex++);
	}
	return getDumpPath(ext);
}


uint32_t stripChars(unsigned char* buf_in, int *output, uint32_t sz, char* chars){
	uint32_t out=0;
	int copy,c;
	unsigned char d;
	unsigned char* buf_out = (unsigned char*)malloc(sz);
	for(int i=0; i<sz; i++){
		copy = 1;
		c = 0;
		d = (unsigned char)buf_in[i];
		while(chars[c] != 0){
			if(d==chars[c]){ copy=0; break; } 
			c++;
		}
		if(copy) (unsigned char)buf_out[out++] = d;
	}
	
	*output = (int)buf_out;
	return out;
}

char* strlower(char* input){
	int sz = strlen(input)+10;
	//printf("allocing %d", sz);
	char* writable = SafeMalloc(sz);
	memset(writable,0,sz);
	for(int i=0; i < sz; i++) writable[i] = tolower(input[i]);
	return writable;
}

int HexToBin(char* input, int* output){

	int sl =  strlen(input)+ 10 + opts.padding;
	void *buf = malloc(sl);
    memset(buf,0,sl);

	//printf("tolower\n");
	char *lower = strlower(input);
	char *h = lower; /* this will walk through the hex string */
	unsigned char *b = (unsigned char*)buf; /* point inside the buffer */

	/* offset into this string is the numeric value */
	char xlate[] = "0123456789abcdef";

	//printf("translating..\n");
	for ( ; *h; h += 2){ /* go by twos through the hex string multiply leading digit by 16 */
	   *b = ((strchr(xlate, *h) - xlate) * 16) + ((strchr(xlate, *(h+1)) - xlate));
	    b++;
	}

	//printf("freeing lower..");
	free(lower);
	*output = (int)buf;
	return sl;
		
}

void nl(void){ printf("\n"); }

bool isDllMemAddress(uint32_t eip){

	if(eip < 0x71ab0000 || eip > 0x7e4a1000){ 
		if( eip < 0x3d930000 || eip > 0x3da01000) return false;
	}
	return true;
}

int disasm_addr(uc_engine *uc, int va, int justDisasm){  //arbitrary offset
	
	int instr_len =0;
	char disasm[200];
	bool isBP = false;

	uint32_t retAddr=0;
	uint32_t m_eip     = va;
	instr_len = emu_disasm_addr(uc, m_eip, disasm); 
	
	int foffset = m_eip - opts.baseAddress;
	if(foffset < 0) foffset = m_eip; //probably a stack address.

	for(int i=0; i < 10; i++){
		if( opts.bpx[i] == m_eip ){ isBP = true; break; }
	}

	start_color( (isBP ? mred : mgreen) );
	if(justDisasm==1){
		printf("%x   %s\n", m_eip, disasm);
	}else if(opts.verbose ==1){
		if(opts.cur_step % 5 == 0){
			printf("%x   %s\t\t step: %i\n", m_eip, disasm, opts.cur_step );
		}else{
			printf("%x   %s\n", m_eip, disasm);
		}
	}else{
		int xx_ret = (int)strstr(disasm,"retn 0x");
		if(xx_ret == 0 && strstr(disasm,"ret") > 0){ //to do this right we have to support retn 0x too...
			emu_memory_read_dword(mem, cpu->reg[esp], &retAddr);
			printf("%x   %s\t\t step: %d  foffset: %x", m_eip, disasm, opts.cur_step,  foffset);
			start_color(mpurple);
			printf(" ret=%x\n", retAddr);
			end_color();
		}else{
			printf("%x   %s\t\t step: %d  foffset: %x\n", m_eip, disasm, opts.cur_step,  foffset);
		}
	}
	end_color();

	return instr_len;

}

void disasm_block(int offset, int size){
	int i, bytes_read, base;
	uint8_t b;
	char disasm[200];
	base = offset;
	for(i=0;i<size;i++){
		bytes_read = emu_disasm_addr(uc, base, disasm); 
		if(bytes_read < 1){
			if(emu_memory_read_byte(mem,base,&b) == -1) break;
			start_color(myellow);
			printf("%x\tdb %X\n", base, b);
			start_color(mgreen);
			base++;
		}else{
			printf("%x\t%s\n", base, disasm);
		}
		base += bytes_read;
	}
}

void xorBuf(unsigned char* buf, uint32_t sz, char* id){
	
	if(strlen(id) > 0) printf("Xor %s input buffer..", id);
	unsigned short *b;
	unsigned int   *c;
	
	int stepSize = 4; //4 byte int val was given..

	if(opts.xorVal == 0) return;
	if((opts.xorVal & 0xFFFF) == opts.xorVal) stepSize = 2; //2 byte short val
	if((opts.xorVal & 0xFF) == opts.xorVal) stepSize = 1;   //single byte 
    
	uint32_t mod = sz % stepSize;
	if(mod!=0){
		printf("size %% %d != 0, wont swap last %d bytes..", stepSize, mod);
		sz -= mod;
	}
	nl();

	for(int i=0; i < sz-(stepSize-1); i += stepSize){
		if(stepSize==1){
			buf[i]^= (unsigned char)opts.xorVal;
		}else if(stepSize==2){
			b = (unsigned short*)&buf[i];
			*b^=(unsigned short)opts.xorVal;
		}else{
			c = (unsigned int*)&buf[i];
			*c^= opts.xorVal;
		}
	}

}

void byteSwap(unsigned char* buf, uint32_t sz, char* id){
	
	if(strlen(id) > 0) printf("Byte Swapping %s input buffer..", id);
	unsigned char a,b;

	uint32_t mod = sz % 2;
	if(mod!=0){
		printf("size %% 2 != 0, wont swap last %d bytes..", mod);
		sz -= mod;
	}
	nl();

	for(int i=0; i < sz-1; i+=2){
		a = buf[i];
        b = buf[i+1];
        buf[i] = b;
		buf[i+1] = a;
	}

}

void endianSwap(unsigned char* buf, uint32_t sz, char* id){
	
	if(strlen(id) > 0) printf("Endian Swapping %s input buffer..", id);
	
	uint32_t mod = sz % 4;
	if(mod!=0){
		printf("size %% 4 != 0, wont swap last %d bytes..", mod);
		sz -= mod;
	}
	nl();

	uint32_t a;
	for(int i=0; i < sz-3; i+=4){
		memcpy(&a, (void*)&buf[i],4);
        a = htonl(a);
        memcpy((void*)&buf[i],&a,4);
	}

}

void real_hexdump(unsigned char* str, int len, int offset, bool hexonly){
	
	char asc[19];
	int aspot=0;
	int i=0;
    int hexline_length = 3*16+4;
	
	char *nl="\n";
	char *tmp = (char*)malloc(75);
    bool color_on = false;
	uint32_t display_rows = -1;
    uint32_t displayed_lines = -1;
	CONSOLE_SCREEN_BUFFER_INFO csb;

	if(GetConsoleScreenBufferInfo( GetStdHandle(STD_OUTPUT_HANDLE) , &csb) !=0){
		display_rows = csb.srWindow.Bottom - csb.srWindow.Top - 2;
	}

	//printf("Display rows: %x\n", display_rows);

	if(!hexonly) printf(nl);
	
	if(offset >=0){
		printf("          0  1  2  3  4  5  6  7   8  9  A  B  C  D  E  F\n");
		printf("%04x   ", offset);
	}

	for(i=0;i<len;i++){

		color_on = false;
		if(str[i] == 0x90 || str[i]== 0xE9 || str[i]== 0xE8 || str[i]== 0xEB) color_on = true;
		//if(color_on && hexdump_color) start_color(myellow);

		sprintf(tmp, "%02x ", str[i]);
		printf("%s",tmp);
		
		//if(color_on && hexdump_color) end_color();

		if( (int)str[i]>20 && (int)str[i] < 123 ) asc[aspot] = str[i];
		 else asc[aspot] = 0x2e;

		aspot++;
		if(aspot%8==0) printf(" "); //to make figuring out offset easier

		if(aspot%16==0){
			asc[aspot]=0x00;
			if(!hexonly){
				displayed_lines++;
				sprintf(tmp,"    %s\n", asc);
				printf("%s",tmp);
				if(display_rows > 0 && displayed_lines == display_rows){
					//if(!opts.automationRun){ 
						displayed_lines = 0;
						printf("-- More --");
						char qq = getch();
						if(qq == 'q') break;
						printf("\n");
					//}
				}
			}
			if(offset >=0){
				offset += 16;
				if(i+1 != len) printf("%04x   ", offset);
			}
			aspot=0;
		}

	}

	if(aspot%16!=0){//print last ascii segment if not full line
		if(!hexonly){
			int spacer = hexline_length - (aspot*3);
			while(spacer--)	printf("%s"," ");	
			asc[aspot]=0x00;
			sprintf(tmp, "%s\n",asc);
			printf("%s",tmp);
		}
	}
	
	if(!hexonly) printf("%s",nl);
	free(tmp);

}

void hexdump(unsigned char* str, int len){ //why doesnt gcc support optional args?
	real_hexdump(str,len,-1,false);
}

void end_color(void){
	//if(opts.no_color) return;
	//printf("\033[0m"); 
	SetConsoleTextAttribute(hConOut,7); 
}
void restore_terminal(int arg)    { SetConsoleMode(hCon, orgt); }
void atexit_restore_terminal(void){ SetConsoleMode(hCon, orgt); }
void start_color(enum colors c){SetConsoleTextAttribute(hConOut, c);}

void color_printf(colors c, const char *format, ...)
{
	DWORD dwErr = GetLastError();
		
	if(format){
		char buf[1024]; 
		va_list args; 
		va_start(args,format); 
		try{
 			 _vsnprintf(buf,1024,format,args);
			 start_color(c);
			 printf("%s",buf);
			 end_color();
		}
		catch(...){}
	}

	SetLastError(dwErr);
}

char* dllFromAddress(uint32_t addr){
	int numdlls=0;
	while ( env->loaded_dlls[numdlls] != 0 ){
		struct emu_env_w32_dll *dll = env->loaded_dlls[numdlls]; 
		if( addr >= dll->baseaddr && addr <= (dll->baseaddr + dll->imagesize) ){
			return dll->dllname;
		}
		numdlls++;
	}
	return strdup(""); //mem leak but no crash choose your fights
}

int fulllookupAddress(int eip, char* buf255){

	int numdlls=0;
	int i=0;
	strcpy(buf255," ");

	/*additional lookup for a couple addresses not in main tables..
	while(mm_points[i].address != 0){
		if(eip == mm_points[i].address){
			strcpy(buf255, mm_points[i].name);
			return 1;
		}
		i++;
	}*/

	while ( env->loaded_dlls[numdlls] != 0 )
	{
		if ( eip == env->loaded_dlls[numdlls]->baseaddr ){
			
			if(eip == 0x7C800000)
				strcpy(buf255, "Kernel32 Base Address");
			else
				sprintf(buf255, "%s Base Address", env->loaded_dlls[numdlls]->dllname );
			
			return 1;
		}
		else if ( eip > env->loaded_dlls[numdlls]->baseaddr && 
			      eip < env->loaded_dlls[numdlls]->baseaddr + 
				            env->loaded_dlls[numdlls]->imagesize )
		{
			struct emu_env_w32_dll *dll = env->loaded_dlls[numdlls];
			void* ehi = (*dll->exports_by_fnptr)[eip - dll->baseaddr];

			if ( ehi == 0 )	return 0;

			struct emu_env_w32_dll_export *ex = (struct emu_env_w32_dll_export *)ehi;
			strncpy(buf255, ex->fnname, 254);
			return 1;

		}
		numdlls++;
	}

	return 0;
}

void symbol_lookup(char* symbol){
	
	bool dllmap_mode = false;

	if(strcmp(symbol,"peb") == 0){
		printf("\tpeb -> 0x00251ea0\n");
		return;
	}

	if(strcmp(symbol,"fs0") == 0){
		printf("\tfs0 -> 0x%x\n", FS_SEGMENT_DEFAULT_OFFSET);
		return;
	}

	if(strcmp(symbol,"dllmap") == 0) dllmap_mode = true;

	int numdlls=0;
	while ( env->loaded_dlls[numdlls] != 0 ){
		 
		struct emu_env_w32_dll *dll = env->loaded_dlls[numdlls];
		
		if(dllmap_mode){
			printf("\t%-8s Dll mapped at %x - %x  Version: %s\n", dll->dllname, dll->baseaddr , dll->baseaddr+dll->imagesize, dll->version);
		}
		else{
			if(strcmp(dll->dllname, symbol)==0){
				printf("\t%s Dll mapped at %x - %x  Version: %s\n", dll->dllname, dll->baseaddr , dll->baseaddr+dll->imagesize, dll->version);
				return;
			}
			
			void* ehi = (*dll->exports_by_fnname)[symbol];
			
			if ( ehi != 0 ){
				int dllBase = dll->baseaddr; 
				struct emu_env_w32_dll_export *ex = (struct emu_env_w32_dll_export *)ehi;
				printf("\tAddress found: %s - > %x\n", symbol, dllBase + ex->virtualaddr);
				return;
			}	
		}
		numdlls++;
	}
	if(!dllmap_mode) printf("\tNo results found...\n");
}


uint32_t symbol2addr(char* symbol){
	if(symbol == NULL) return 0;
	if(strcmp(symbol,"peb") == 0) return 0x00251ea0;
	if(strcmp(symbol,"fs0") == 0) return FS_SEGMENT_DEFAULT_OFFSET;
	int numdlls=0;
	while ( env->loaded_dlls[numdlls] != 0 ){
		struct emu_env_w32_dll *dll = env->loaded_dlls[numdlls]; 
		void* ehi = (*dll->exports_by_fnname)[symbol];	
		if ( ehi != 0 ){ 
			struct emu_env_w32_dll_export *ex = (struct emu_env_w32_dll_export *)ehi;
			return dll->baseaddr + ex->virtualaddr;
		}	
		numdlls++;
	}
	return 0;
}

int findFreeBPXSlot(void){
	for(int i=0; i < 10; i++){
		if(opts.bpx[i] == 0) return i;
	}
	return -1;
}

void showEipLog(void){
	nl();
	for(int i=0;i < eip_log_sz;i++){
		if(eip_log[i] == 0) break; 
		disasm_addr(env->uc, eip_log[i]);
	}
}

void logEip(uint32_t eip){
	
	for(int i=0;i < eip_log_sz;i++){
		if(eip_log[i] == 0){  //initial fill
			eip_log[i] = eip;
			return;
		} 
	}

	for(int i=1;i < eip_log_sz;i++){
		eip_log[i-1] = eip_log[i];
	}

	eip_log[ eip_log_sz-1 ] = eip;
}


void do_memdump(void){
	
	unsigned char* tmp ;
	char* tmp_path = 0;
	char* extension[200];
	int ii;
	FILE *fp;

	printf("Primary memory: Reading 0x%x bytes from 0x%x\n", opts.size, opts.baseAddress);
	tmp = (unsigned char*)malloc(opts.size);

	if(emu_memory_read_block(mem, opts.baseAddress, tmp,  opts.size) == -1){
		printf("ReadBlock failed!\n");
	}else{
   	 
		printf("Scanning for changes...\n");
		for(ii=0;ii<opts.size;ii++){
			if(opts.scode[ii] != tmp[ii]) break;
		}

		if(ii < opts.size){
			tmp_path = getDumpPath("unpack");
			start_color(myellow);
			printf("Change found at %i dumping to %s\n",ii,tmp_path);
			fp = fopen(tmp_path, "wb");
			if(fp==0){
				printf("Failed to create file\n");
			}else{
				fwrite(tmp, 1, opts.size, fp);
				fclose(fp);
				printf("Data dumped successfully to disk\n");
			}
			end_color();
			free(tmp_path);
		}else{
			printf("No changes found in primary memory, dump not created.\n");
		}

	}

	free(tmp);

	if( malloc_cnt > 0 ){ //then there were allocs made..
		
		start_color(myellow);
		printf("Dumping %d runtime memory allocations..\n", malloc_cnt);
		
		for(ii=0; ii < malloc_cnt; ii++){
		
			tmp = (unsigned char*)malloc(mallocs[ii].size);

			if(emu_memory_read_block(mem, mallocs[ii].base, tmp,  mallocs[ii].size) == -1){
				printf("ReadBlock failed! base=%x size=%x\n", mallocs[ii].base, mallocs[ii].size );
			}else{
				sprintf((char*)extension,"alloc_0x%x",mallocs[ii].base);
				tmp_path = getDumpPath( (char*)extension);
				fp = fopen(tmp_path, "wb");
				if(fp==0){
					printf("Failed to create file\n");
				}else{
					fwrite(tmp, 1, mallocs[ii].size, fp);
					fclose(fp);
					printf("Alloc %x (%x bytes) dumped successfully to disk as %s\n", mallocs[ii].base, mallocs[ii].size, tmp_path);
				}
				free(tmp_path);
			}

			free(tmp);
		}

		end_color();
			
	}

	//if(tmp_path) free(tmp_path);
}

void min_window_size(void){
	CONSOLE_SCREEN_BUFFER_INFO sb;
	COORD maxb;
	BOOL ret = false;
	bool changed = false;
	SMALL_RECT da = {0, 0, 0, 0}; 
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    maxb = GetLargestConsoleWindowSize(hOut);
	GetConsoleScreenBufferInfo(hOut, &sb); 
	da = sb.srWindow;
	if(sb.srWindow.Right < 100 && maxb.X > 100){ da.Right = 100; changed = true;}
	if(sb.srWindow.Bottom < 40 && maxb.Y > 40){  da.Bottom = 40; changed = true;}
	maxb.X = da.Right + 1;
	maxb.Y = da.Bottom * 5;
	if(changed){
		ret = SetConsoleScreenBufferSize(hOut, maxb);
		//printf("Change buffer: %x\n", ret);
		ret = SetConsoleWindowInfo(hOut,TRUE,&da);
		//printf("SetInfo: %x\n", ret);
	}
}

void loadsc(void){

	FILE *fp;
	int tmp;
	int tmp2;
    int j=0;

	if(opts.hexInMode){
		color_printf(myellow, "Converting hexin to binary...");
		opts.size = HexToBin((char*)opts.scode, &tmp2);
		free(opts.scode);
		opts.scode = (unsigned char*)tmp2;
		return;
	}

	if (opts.nofile || (opts.patch_file != NULL && opts.file_mode == false) ){ 
		//create a default allocation to cover any assumptions
		opts.scode = (unsigned char*) malloc(0x1000 + opts.padding);
		opts.size = 0x1000 + opts.padding;
		memset(opts.scode, 0, opts.size); 
		return;
	}
	
	fp = fopen(opts.sc_file, "rb");
	if(fp==0){
		start_color(myellow);
		printf("Failed to open file %s\n",opts.sc_file);
		end_color();
		m_exit(0);
	}
	opts.size = file_length(fp) + opts.padding ;
	opts.scode = (unsigned char*)malloc(opts.size+10); 
	memset(opts.scode, 0, opts.size+10);
	fread(opts.scode, 1, opts.size - opts.padding, fp);
	fclose(fp);
	if(!opts.automationRun) printf("Loaded %x bytes from file %s\n", opts.size, opts.sc_file);
	 
	if(opts.size==0){
		printf("No shellcode loaded must use either /f or /S options\n");
		show_help();
		return;
	}

	for(j=0; j<opts.size; j++){ //scan the buffer and ignore possible leading white space and quotes...
		unsigned char jj = opts.scode[j];
		if(jj != ' ' && jj != '\r' && jj != '\n' && jj != '"' && jj != '\t' && jj != '\'') break;
	}
	if(j >= opts.size-1) j = 0;

	if( (opts.scode[j] == '%' && opts.scode[j+1] == 'u') || (opts.scode[j] == '\\' && opts.scode[j+1] == 'u') ){
		start_color(colors::myellow);
		printf("Detected %%u encoding input format converting...\n");
		end_color();
		//printf("stripping..\n");
		opts.size = stripChars((unsigned char*)opts.scode, &tmp, opts.size, "\n\r\t,%u\";\' +\\"); 
		free(opts.scode);
		printf("to bin..\n");
		opts.size = HexToBin((char*)tmp, &tmp2);
		opts.scode = (unsigned char*)tmp2;
		//printf("swapping..\n");
		byteSwap(opts.scode, opts.size, "%u encoded"); 
	}else if(opts.scode[j] == '%' && opts.scode[j+3] == '%'){
		start_color(colors::myellow);
		printf("Detected %% hex input format converting...\n");
		end_color();
		opts.size = stripChars((unsigned char*)opts.scode, &tmp, opts.size, "\n\r\t,%\";\' +"); 
		free(opts.scode);
		opts.size = HexToBin((char*)tmp, &tmp2);
		opts.scode = (unsigned char*)tmp2;		
	}else if(opts.scode[j] == '\\' && opts.scode[j+1] == 'x'){
		start_color(colors::myellow);
		printf("Detected \\x encoding input format converting...\n");
		end_color();
		opts.size = stripChars((unsigned char*)opts.scode, &tmp, opts.size,"\n\r\t,\\x\";\' " ); 
		free(opts.scode);
		opts.size = HexToBin((char*)tmp, &tmp2);
		opts.scode = (unsigned char*)tmp2;
	}else if(isxdigit(opts.scode[j]) && isxdigit(opts.scode[j+1]) && isxdigit(opts.scode[j+2]) && isxdigit(opts.scode[j+3]) ){
		bool allHex = true;
		unsigned char* tmp3 = (unsigned char*)SafeMalloc(opts.size);
		memcpy(tmp3,opts.scode, opts.size);
		uint32_t newSize = stripChars(tmp3, &tmp, opts.size,"\n\r\t,\\ \";\'" ); 
		unsigned char* c = (unsigned char*)tmp;
		for(int i=0;i < newSize; i++){
			if(!isxdigit(c[i])) allHex = false; 
			if(!allHex){
				//printf("failed at offset %x/%x value: %d memoffset %x\n", i,opts.size, c[i], &c[i]);
				break;
			}
		}
		free(tmp3);
		if(!allHex) return;
		start_color(colors::myellow);
		printf("Detected straight hex encoding input format converting...\n");
		end_color();
		opts.size = stripChars((unsigned char*)opts.scode, &tmp, opts.size,"\n\r\t,\\ \";\'" ); 
		free(opts.scode);
		opts.size = HexToBin((char*)tmp, &tmp2);
		opts.scode = (unsigned char*)tmp2;
	}

}


void IDASync(uint32_t eip){
	if(opts.IDASrvrHwnd == 0) return;
	if(!IsWindow(opts.IDASrvrHwnd)){ opts.IDASrvrHwnd = 0; return;	}
	uint32_t adjustedOffset = eip;
	if(opts.IDAImgBase == 0) adjustedOffset -= opts.baseAddress; //they disam as raw binary file no rebase or exe

	SendMessage(opts.IDASrvrHwnd, IDA_QUICKCALL_MESSAGE, 1, adjustedOffset);  //jmp:lngAdr 
	SendMessage(opts.IDASrvrHwnd, IDA_QUICKCALL_MESSAGE, 43, 0); //SetFocusSelectLine

	for(int i=0; i<5; i++){ //can require an unknown delay
		Sleep(200);
		SetForegroundWindow( GetConsoleWindow() ); //steal it back. I am assuming you have enough screen realestate to display both at once to avoid flicker back and forth..
		if( GetForegroundWindow() == GetConsoleWindow() ) break;
	}

}

int IDASendTextMessage(HWND hwnd, char *buf) 
{
	  int blen = strlen(buf);
	  if(buf[blen] != 0) buf[blen]=0; ;
	  cpyData cpStructData;  
	  cpStructData.cbSize = blen;
	  cpStructData.lpData = (int)buf;
	  cpStructData.dwFlag = 3;
	  return SendMessage((HWND)hwnd, WM_COPYDATA, (WPARAM)hwnd,(LPARAM)&cpStructData);  
}

void IDASetComment(uint32_t eip, char* cmt){
	if(!cmt) return;
	if(opts.IDASrvrHwnd == 0) return;
	if(!IsWindow(opts.IDASrvrHwnd)){ opts.IDASrvrHwnd = 0; return;	}
	
	uint32_t adjustedOffset = eip;
	if(opts.IDAImgBase == 0) adjustedOffset -= opts.baseAddress; //they disam as raw binary file no rebase or exe

	char* buf = SafeMalloc(strlen(cmt) + 100);
	sprintf(buf, "addcomment:%d:%s", adjustedOffset, cmt);
	IDASendTextMessage(opts.IDASrvrHwnd,buf);
	free(buf);
}


HWND IDASrvrHWND(void){

	 char* baseKey = "Software\\VB and VBA Program Settings\\IPC\\Handles";
	 char tmp[20] = {0};
     unsigned long l = sizeof(tmp);
	 HWND ret=0;
	 HKEY h;
	 
	 RegOpenKeyExA(HKEY_CURRENT_USER, baseKey, 0, KEY_READ, &h);
	 RegQueryValueExA(h, "IDA_SERVER", 0,0, (unsigned char*)tmp, &l);
	 RegCloseKey(h);
	
	 ret = (HWND)atoi(tmp);
	 if(!IsWindow(ret)) ret = 0;
	 return ret;
}

void IDAConnect(void){
	char buf[100] ={"Unknown"};
	opts.IDASrvrHwnd = IDASrvrHWND();
	if(opts.IDASrvrHwnd != 0){
		opts.IDAImgBase = SendMessage( opts.IDASrvrHwnd, IDA_QUICKCALL_MESSAGE, 8, 0);
		HWND mainWindow = (HWND)SendMessage( opts.IDASrvrHwnd, IDA_QUICKCALL_MESSAGE, 41, 0);
		GetWindowTextA(mainWindow, &buf[0], 99);
		printf("Connected to: %s\n", buf);
		IDASync(cpu->eip);
		 
	}else{
		printf("No open instances of IDA found. Is IDASrvr plugin installed?\n");
	}
}
