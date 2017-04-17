
#include "lib.h"


void show_help(void)
{
	struct help_info 
	{
		const char *short_param;
		const char *args;
		const char *description;
	};

	struct help_info help_infos[] =
	{
		{"f", "fpath"    ,   "load shellcode from file - accepts binary, %u, \\x, %x, hex blob"},
		{"d",  NULL	     ,   "dump unpacked shellcode"},
		{"foff", "hexnum" ,  "starts execution at file offset (also supports virtual addresses)"},
		{"h",  NULL		 ,   "show this help"},
		{"hooks", NULL ,     "dumps a list all implemented api hooks"},
		{"i",  NULL		 ,   "enable interactive hooks (file and network)"},
		{"e", "int"	     ,   "verbosity on error (3 = debug shell)"},
		{"las", "int"	 ,   "log at step ex. -las 100"},
		{"laa", "hexnum" ,   "log at address or api ex. -laa 0x401020 or -laa ReadFile"},
		{"lookup", "api" ,   "shows the address of WinAPi function ex. -lookup GetProcAddress"},
		{"o", "hexnum"   ,   "base offset to use (default: 0x401000)"},
		{"pad", "0xVal",     "add an extra 0xVal bytes to shellcode"},
		{"s", "int"	     ,   "max number of steps to run (def=2000000, -1 unlimited)"},	
		{"u", NULL ,         "unlimited steps (same as -s -1)"},
		{"v",  NULL		 ,   "verbosity, can be used up to 4 times, ex. /v /v /vv"},
		{"hexin",  "hexstr"	,"load a hex string from command line"},
	};

	system("cls");
	start_color(mwhite);
	printf("\n\n");
	printf("  stripped version of scdbg for testing\n");
	printf("  Libemu Copyright (C) 2007  Paul Baecher & Markus Koetter\n");
	printf("  Unicorn Engine Copyright (C) 2015 Nguyen Anh Quynh and Dang Hoang Vu\n");
	printf("  libdasm (c) 2004 - 2006  jt / nologin.org\n");
	printf("  scdbg developer: David Zimmer <dzzie@yahoo.com>\n");
	printf("  libemu/unicorn shim layer contributed by FireEye FLARE team\n");
	printf("  GDT setup code Copyright(c) 2016 Chris Eagle\n");
	printf("  Compile date: %s %s\n\n", __DATE__, __TIME__);
	end_color();

	for (int i=0;i<sizeof(help_infos)/sizeof(struct help_info); i++)
	{
		printf("  /%1s ", help_infos[i].short_param);

		if (help_infos[i].args != NULL)
			printf("%-12s ", help_infos[i].args);
		else
			printf("%12s "," ");

		printf("\t%s\n", help_infos[i].description);
	}

	m_exit(0);

}





void show_supported_hooks(void){
	
	uint32_t i=0;
	uint32_t j=0;
	uint32_t tot=0;
	uint32_t iHooks=0;
	uint32_t proxied=0;

	//set_hooks(env);

	while ( env->loaded_dlls[i] != 0 ){
		struct emu_env_w32_dll *dll = env->loaded_dlls[i]; 
		printf("\r\n%s\r\n", dll->dllname );
		emu_env_w32_dll_export e = dll->exportx[0];
		while( e.fnname != NULL ){
			if( e.fnhook != 0 ){
				if( strlen(e.fnname) == 0){
					if(opts.verbose > 0) printf("\t  @%-29x =  0x%x\r\n", e.ordinal, e.virtualaddr + dll->baseaddr);
					 else printf("\t  @%x\r\n", e.ordinal);
				}else{
					if(opts.verbose > 0) printf("\t  %-30s  =  0x%x\r\n", e.fnname, e.virtualaddr + dll->baseaddr);
					 else printf("\t  %s\r\n", e.fnname);
				}				
				tot++;
			}
			j++;
			e = dll->exportx[j];
		}
		i++;
		j=0;
	}
	printf("\r\n  Dlls: %d\r\n  Hooks: %d\r\n", i, tot);
	exit(0);
}



void parse_opts(int argc, char* argv[] ){

	int i;
    uint32_t bp=0;

	//opts structure was already memset(0) in main 
	opts.sc_file[0] = 0;
	opts.opts_parsed = 1;
	opts.offset = 0;
	opts.steps = 2000000;
	opts.file_mode = false;
	opts.dump_mode = false;
	opts.baseAddress = 0x00401000;

	for(i=1; i < argc; i++){

		bool handled = false;			

		if( argv[i][0] == '-') argv[i][0] = '/'; //standardize

		std::string opt = argv[i];
		std::transform(opt.begin(), opt.end(), opt.begin(), tolower);

		if(opt == "/i"){opts.interactive_hooks = 1;handled=true;}
		if(opt == "/v"){opts.verbose++; handled=true;}
		if(opt == "/u"){opts.steps = -1;handled=true;}
		if(opt == "/vvvv"){handled=true; opts.verbose = 4;}
		if(opt == "/vvv") { opts.verbose = 3;handled=true;}
		if(opt == "/vv") { opts.verbose = 2;handled=true;}
		if(opt == "/hooks"){ show_supported_hooks();handled=true;} //supports -v (must specify first though)
		if(opt == "/d"){ opts.dump_mode = true;handled=true;}
		if(opt == "/h"){ show_help();handled=true;}
		if(opt == "/?"){ show_help();handled=true;}
		if(opt == "/help"){ show_help();handled=true;}
		if(opt == "/dllmap"){ nl(); symbol_lookup("dllmap");exit(0);}

		if(opt == "/f"){
			if(i+1 >= argc){
				color_printf(myellow, "Invalid option /f must specify a file path as next arg\n");
				m_exit(0);
			}
			strncpy(opts.sc_file, argv[i+1],499);
			opts.file_mode = true;
			i++;handled=true;
		}

		if(opt == "/e"){
			if(i+1 >= argc){
				color_printf(myellow, "Invalid option /e must specify err verbosity as next arg\n");
				m_exit(0);
			}
		    opts.verbosity_onerr = atoi(argv[i+1]);			
			i++;handled=true;
		}

        if(opt == "/bp"){ 
			if(i+1 >= argc){
				color_printf(myellow, "Invalid option /bp must specify hex breakpoint addr as next arg\n");
				m_exit(0);
			}
			int bpi= findFreeBPXSlot();
			if(bpi == -1){
				printf("Only 10 breakpoints are supported\n");
				m_exit(0);
			}
			bp = symbol2addr(argv[i+1]);
			if(bp == 0) bp = strtol(argv[i+1], NULL, 16);     //it wasnt a symbol must be a hex offset
			if(bp == 0){
				color_printf(myellow, "Could not set breakpoint %s\n", argv[i+1]);
				m_exit(0);
			}
			opts.bpx[bpi] = bp;
			printf("Breakpoint %d set at %x\n", bpi, opts.bpx[bpi]);
			i++; handled = true;
		}

        if(opt == "/lookup"){
			if(i+1 >= argc){
				color_printf(myellow, "Invalid option /lookup must specify an API name as next arg\n");
				m_exit(0);
			}
			uint32_t addr = symbol2addr(argv[i+1]);
			if( addr == 0)
				color_printf(myellow, "\nNo results found for: %s\n\n",argv[i+1]);
			else
				color_printf(myellow, "\n%s = 0x%x\n\n",argv[i+1],addr);
			m_exit(0);
			
		}
		
		if(opt == "/o"){
			if(i+1 >= argc){
				color_printf(myellow, "Invalid option /o must specify a hex base addr as next arg\n");
				m_exit(0);
			}
		    opts.baseAddress = strtol(argv[i+1], NULL, 16);			
			i++;handled=true;
		}

		if(opt == "/foff"){
			if(i+1 >= argc){
				color_printf(myellow, "Invalid option /foff must specify start file offset as next arg\n");
				m_exit(0);
			}
			opts.offset = strtol(argv[i+1], NULL, 16);
			i++;handled=true;
		}

		if(opt == "/hexin"){
			if(i+1 >= argc){
				color_printf(myellow, "Invalid option /hexin must specify shellcode hex string as next arg\n");
				m_exit(0);
			}
			opts.scode = (unsigned char*)strdup(argv[i+1]); //converted in loadsc
			opts.hexInMode = true;
			opts.nofile = true;
			i++;handled=true;
		}

		if(opt == "/laa"){
			if(i+1 >= argc){
				color_printf(myellow, "Invalid option /laa must specify a hex addr as next arg\n");
				m_exit(0);
			}
			opts.log_after_va = symbol2addr(argv[i+1]);
			if(opts.log_after_va == 0) opts.log_after_va = strtol(argv[i+1], NULL, 16);	
			i++;handled=true;
		}

		if(opt == "/las"){
			if(i+1 >= argc){
				color_printf(myellow, "Invalid option /las must specify a integer as next arg\n");
				m_exit(0);
			}
		    opts.log_after_step  = atoi(argv[i+1]);		
			i++;handled=true;
		}

		if(opt == "/s"){
			if(i+1 >= argc){
				color_printf(myellow, "Invalid option /s must specify num of steps as next arg\n");
				m_exit(0);
			}
		    opts.steps = atoi(argv[i+1]);	
			i++;handled=true;
		}

        if( !handled ){
			color_printf(myellow, "Unknown Option %s\n\n", argv[i]);
			m_exit(0);
		}

	}


}