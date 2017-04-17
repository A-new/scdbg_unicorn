
this is a slightly stripped down version of scdbg to test the
libemu win32 env shim and to get it working with the Unicorn engine
emulator.

all 268 api hooks and 15 dlls are in place

compiled binaries are in the /bin folder

scdbg -h
scdbg -hooks
scdbg -dllmap

some command line, debug shell, and memory monitor options have been 
stripped out until I have a chance to really go through and test them 
all.

this build is primarily aimed at testing the shim layer and bringing
the hooks in.

these project files are for VS2008. If your compiler is missing stdint.h
you can copy the files in /stdint to your compilers default include directory.

many thanks to all of the authors involved.

scdbg -h

  stripped version of scdbg for testing
  Libemu Copyright (C) 2007  Paul Baecher & Markus Koetter
  Unicorn Engine Copyright (C) 2015 Nguyen Anh Quynh and Dang Hoang Vu
  libdasm (c) 2004 - 2006  jt / nologin.org  scdbg developer: David Zimmer <dzzie@yahoo.com>
  libemu/unicorn shim layer contributed by FireEye FLARE team
  Compile date: Jan 31 2017 06:37:17

  /f fpath              load shellcode from file - accepts binary, %u, \x, %x, hex blob
  /d                    dump unpacked shellcode
  /foff hexnum          starts execution at file offset (also supports virtual addresses)
  /h                    show this help
  /hooks                dumps a list all implemented api hooks
  /i                    enable interactive hooks (file and network)
  /e int                verbosity on error (3 = debug shell)
  /las int              log at step ex. -las 100
  /laa hexnum           log at address or api ex. -laa 0x401020 or -laa ReadFile
  /lookup api           shows the address of WinAPi function ex. -lookup GetProcAddress
  /o hexnum             base offset to use (default: 0x401000)
  /pad 0xVal            add an extra 0xVal bytes to shellcode
  /s int                max number of steps to run (def=2000000, -1 unlimited)
  /u                    unlimited steps (same as -s -1)
  /v                    verbosity, can be used up to 4 times, ex. /v /v /vv
  /hexin hexstr         load a hex string from command line



debug shell help:

dbg>
        ? - help, this help screen, h also works
        v - change verbosity (0-4)
        g - go - continue with v=0
        s - step, continues execution, ENTER also works
        u - unassembled x instructions at address (default eip)
        e - set eip (file offset or VA)
        w - dWord dump,(32bit ints) prompted for hex base addr and then size
        d - Dump Memory (hex dump) prompted for hex base addr and then size
        k - show stack
        f - dereF registers (show any common api addresses in regs)
        j - show log of last 10 instructions executed
        q - quit



Credits:
---------------------------------------------------------------------------------

	Libemu   Copyright (C) Paul Baecher & Markus Koetter
	License: GPL

	Unicorn  Copyright (C) Nguyen Anh Quynh and Dang Hoang Vu
        Site:    http://www.unicorn-engine.org/
	License: GPL

	QEMU
	Site:    http://qemu.org
	License: GPL

	scdbg    Copyright (C) David Zimmer
	Site:    http://sandsprite.com
	License: GPL

        libemu / Unicorn compatibility shim layer 
        Contributed by FireEye FLARE team
        License: GPL
       
        GDT setup code
        Copyright(c) 2016 Chris Eagle
        License: GPL



