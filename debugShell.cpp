//taken from scdbg and stripped down for simplicity in our test project..

#include "lib.h"

#define INT32_MAX 0x7fffffff

void show_disasm(){  //current line

	uint32_t m_eip = emu_cpu_eip_get(uc);

	disasm_addr(uc, m_eip);

	/*if(opts.time_delay > 0){
		if(opts.verbose ==1 || opts.verbose ==2) Sleep(opts.time_delay);
	}*/

}


uint32_t isString(uint32_t va, uint32_t max_len){ //returns string length
	bool retval = 0;
	char* buf = (char*)malloc(max_len);
	if( emu_memory_read_block(env->uc, va, buf, max_len) != -1 ){
		for(int i=0;i<max_len;i++){
			unsigned char c = buf[i];
			//61 7A 41 5A 30 31 39 21  3F 2E   azAZ019!?.
			if( isalnum(c)==0 ){
				if( c !='!' && c !='.' && c!='?' && c!=':' && c!='\\' && c!='/' && c!=';' && c!='=') break; 
			}
			retval++;
		}
	}
	free(buf);
	return retval;
}

bool derefStringAddr(struct emu_string* s, uint32_t va, uint32_t len){
		uint32_t slen = isString(va, len);
		if(slen > 1){
			emu_memory_read_string(env->uc, va, s, slen);
			return true;
		}else{
			emu_string_clear(s);
			return false;
		}
}

void show_stack(void){
	
	int i=0;
	//uint32_t curesp = emu_cpu_reg32_get(cpu , emu_reg32::esp);
	uint32_t curesp = emu_reg32_read(env->uc,esp);
	uint32_t mretval=0;
	char buf[255];
	struct emu_string* es = emu_string_new();

	for(i = -16; i<=24;i+=4){
		emu_memory_read_dword(env->uc,curesp+i,&mretval);
		fulllookupAddress(mretval, (char*)&buf);
		derefStringAddr(es, mretval, 256); 
		if(i < 0){
			printf("[ESP - %-2x] = %08x\t%s\t%s\n", abs(i), mretval, buf, es->data);
		}else if(i==0){
			printf("[ESP --> ] = %08x\t%s\t%s\n", mretval, buf, es->data);
		}else{
			printf("[ESP + %-2x] = %08x\t%s\t%s\n", i, mretval, buf, es->data);
		}
	}

	emu_string_free(es);
	
}

unsigned int read_int(char* prompt, char* buf){
	unsigned int base = 0;
	uint32_t nBytes = 20;
	int i=0;

	printf("%s: (int/reg) ", prompt);
//	getline(&buf, &nBytes, stdin);
	fgets(buf, nBytes, stdin); 


	if(strlen(buf)==4){
		for(i=0;i<8;i++){
			if(strstr(buf, regm[i]) > 0 ){
				base = emu_reg32_read(env->uc, (emu_reg32)i);
				//printf("found register! %s = %x\n", regm[i], base);
				break;
			}
		}
	}
	
	if(strstr(buf, "eip") > 0 ) base =  emu_cpu_eip_get(env->uc);

	if(base==0) base = atoi(buf);
	printf("%d\n",base);

	return base;
}

unsigned int read_hex(char* prompt, char* buf){
	unsigned int base = 0;
	uint32_t nBytes = 20;
	int i=0;

	printf("%s: (hex/reg) 0x", prompt);
//	getline(&buf, &nBytes, stdin);
	fgets(buf, nBytes, stdin); 

	if(strlen(buf)==4){
		for(i=0;i<8;i++){
			if(strstr(buf, regm[i]) > 0 ){
				base = emu_reg32_read(env->uc, (emu_reg32)i);
				//printf("found register! %s = %x\n", regm[i], base);
				break;
			}
		}
	}

	if(strstr(buf, "eip") > 0 ) base = emu_cpu_eip_get(env->uc);
	if(strstr(buf, "base") > 0 ) base = opts.baseAddress;
	if(strstr(buf, "size") > 0 ) base = opts.size;

	if(base==0){
		base = strtol(buf, NULL, 16); //support negative numbers..
		if(base == INT32_MAX) base = strtoul(buf, NULL, 16); //but in this case assume unsigned val entered
	}

	printf("%x\n",base);

	return base;
}

void deref_regs(void){

	int i=0;
	int output_addr = 0;
	char ref[255];
	uint32_t r = 0;

	for(i=0;i<8;i++){
		r = emu_reg32_read(env->uc, (emu_reg32)i);
		if( fulllookupAddress( r, (char*)&ref) > 0 ){
			printf("\t%s -> %s\n", regm[i], ref);
			if(output_addr++==3) nl();
		}
	}
	
	struct emu_string* s = emu_string_new();
	bool first = true;

	for(i=0;i<8;i++){
		r = emu_reg32_read(env->uc, (emu_reg32)i);
		uint32_t slen = isString(r, 20);
		if(slen > 0){
			emu_memory_read_string(env->uc, r, s, slen);
			if( first ){ printf("\n"); first = false; }
			printf("\t%s -> ASCII: %s %d\n", regm[i], s->data, slen);
			output_addr++;
		}
	}
	
	emu_string_free(s);

	if(output_addr==0) printf("No known values found...");
	nl();
}





void show_debugshell_help(void){
	printf( 
			"\n"
			"\t? - help, this help screen, h also works\n"
			"\tv - change verbosity (0-4)\n"
			"\tg - go - continue with v=0 \n"
			"\ts - step, continues execution, ENTER also works\n"
			/*"\tc - reset step counter\n"
			"\tr - execute till return (v=0 recommended)\n"*/
			"\tu - unassembled x instructions at address (default eip)\n"
			/*"\tb - sets next free breakpoint (10 max)\n"
			"\tm - reset max step count (-1 = infinate)\n"*/
			"\te - set eip (file offset or VA)\n"
			"\tw - dWord dump,(32bit ints) prompted for hex base addr and then size\n"
			"\td - Dump Memory (hex dump) prompted for hex base addr and then size\n"
			/*"\tx - execute x steps (use with reset step count)\n"
			"\tt - set time delay (ms) for verbosity level 1/2\n"*/
			"\tk - show stack\n"
			//"\ti - break at instruction (scans disasm for next string match)\n"
			"\tf - dereF registers (show any common api addresses in regs)\n" 
			"\tj - show log of last 10 instructions executed\n" 
			/*"\to - step over\n" 
			"\t; - Set comment in IDA if .idasync active\n" 
			"\t+/- - basic calculator to add or subtract 2 hex values\n"
			"\t.bl - list set breakpoints\n"
			"\t.bc - clear breakpoint\n"
			"\t.api - scan memory for api table\n"
			"\t.nop - nops out instruction at address (default eip)\n"
			"\t.seh - shows current value at fs[0]\n"
			"\t.segs - show values of segment registers\n"
			"\t.skip - skips current instruction and goes to next\n"
			"\t.reg - manually set register value\n"
			"\t.dllmap - show dll map\n"
			"\t.poke1 - write a single byte to memory\n"
			"\t.poke4 - write a 4 byte value to memory\n"
			"\t.lookup - get symbol for address\n"  
			"\t.symbol - get address for symbol (special: peb,dllmap,fs0)\n" 
			"\t.savemem - saves a memdump of specified range to file\n"
			"\t.idasync - connect IDASrvr plugin and sync view at step or break.\n"
			"\t.allocs - list memory allocations made\n"*/
			"\tq - quit\n\n"
		  );
}



void interactive_command(){

	printf("\n");
    
	//if( opts.automationRun ) return;
	//disable_mm_logging = true;

	char *buf=0;
	char *tmp = (char*)malloc(161);
	char lookup[255];
	uint32_t base=0;
	uint32_t size=0;
	uint32_t i=0;
	uint32_t bytes_read=0;
	char x[2]; x[1]=0;
    char c=0;;
	struct emu_string *es = emu_string_new();

	while(1){

		if( (c >= 'a' || c==0) && c != 0x7e) printf("dbg> "); //stop arrow and function key weirdness...
		if( c == '.') printf("dbg> ");

		c = getch();

		if(c=='g'){ opts.verbose = 0; break; }
		if(c=='q'){ exit(0); break; }
		if(c=='j') showEipLog();
		if(c=='f') deref_regs();
		if(c=='k'){ nl(); show_stack(); nl();}
		if(c=='s' || c== 0x0A) break;
		if(c=='?' || c=='h') show_debugshell_help();

		if(c=='v'){
			printf("Enter desired verbosity (0-4):");
			x[0] = getchar();
			opts.verbose = atoi(x);
			printf("%i\n", opts.verbose );
		}

		if(c=='e'){
			base = read_hex("Set eip (VA or file offset) ", tmp);
			if(base==0){ printf("Failed to get value...\n");}
			else{ 
				//if(base < opts.baseAddress) base += opts.baseAddress; //allow them to enter file offsets			
				emu_cpu_eip_set(uc, base);
				disasm_addr(uc,base);
				//IDASync(base);
			}
		}

		if(c=='u'){
			base = read_hex("Disassemble address (default eip)",tmp);
			if(base==0){
				base = emu_cpu_eip_get(uc); size = 5;
			}else{
				size = read_int("Number of instructions to dump (max 100)", tmp);
				if(size==0) size = 5;
			}
			if(size > 100) size = 100;
			for(i=0;i<size;i++){
				bytes_read = disasm_addr(uc,base);
				if(bytes_read < 1) break;
				base += bytes_read;
			}
		}

		if(c=='d'){
			base = read_hex("Enter hex base to dump", tmp);
			size = read_hex("Enter hex size",tmp);

			buf = (char*)malloc(size);
			if(emu_memory_read_block(uc, base, buf,  size) == -1){
				printf("Memory read failed...\n");
			}else{
				real_hexdump((unsigned char*)buf,size,base,false);
			}
			free(buf);

		}

		if(c=='w'){
			base = read_hex("Enter hex base to dump", tmp);
			size = read_hex("Enter words to dump",tmp);
			int rel = read_int("Offset mode 1,2,-1,-2 (abs/rel/-abs/-rel)", tmp);			
			if(rel==0) rel = 1;
			//size*=4; //num of 4 byte words to show, adjust for 0 based
		
			if( rel < 1 ){
				for(i=base-size;i<=base;i+=4){
					if(emu_memory_read_dword(uc, i, &bytes_read) == -1){
						printf("Memory read of %x failed \n", base );
						break;
					}else{
						fulllookupAddress(bytes_read,(char*)&lookup);
						derefStringAddr(es,bytes_read, 50);
						if(rel == -2){
							printf("[x - %-2x]\t%08x\t%s\t%s\n", (base-i), bytes_read, lookup, es->data );
						}else{
							printf("%08x\t%08x\t%s\t%s\n", i, bytes_read, lookup, es->data);
						}
					}
				}
			}else{
				for(i=0;i<=size;i+=4){
					if(emu_memory_read_dword(uc, base+i, &bytes_read) == -1){
						printf("Memory read of %x failed \n", base+i );
						break;
					}else{
						derefStringAddr(es,bytes_read, 50);
						fulllookupAddress(bytes_read,(char*)&lookup);
						if(rel == 2){
							printf("[x + %-2x]\t%08x\t%s\t%s\n", i, bytes_read, lookup, es->data );
						}else{
							printf("%08x\t%08x\t%s\t%s\n", base+i, bytes_read, lookup, es->data);
						}
					}
				}
			}
		}
				

	}

	printf("\n");
	free(tmp);
	emu_string_free(es);
}



