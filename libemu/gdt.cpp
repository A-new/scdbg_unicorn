/*

Sample code to setup a GDT, and use segments.

Copyright(c) 2016 Chris Eagle

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
version 2 as published by the Free Software Foundation.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

https://github.com/unicorn-engine/unicorn/blob/master/samples/sample_x86_32_gdt_and_seg_regs.c

- modified for our use -dz 2.1.17

*/

#include <inttypes.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>

#include "./../lib.h"

#pragma pack(push, 1)
struct SegmentDescriptor {
   union {
      struct {   
         unsigned short limit0;
         unsigned short base0;
         unsigned char base1;
         unsigned char type:4;
         unsigned char system:1;      /* S flag */
         unsigned char dpl:2;
         unsigned char present:1;     /* P flag */
         unsigned char limit1:4;
         unsigned char avail:1;
         unsigned char is_64_code:1;  /* L flag */
         unsigned char db:1;          /* DB flag */
         unsigned char granularity:1; /* G flag */
         unsigned char base2;
      };
      uint64_t desc;
   };
};
#pragma pack(pop)

//#define SEGBASE(d) ((uint32_t)((((d).desc >> 16) & 0xffffff) | (((d).desc >> 32) & 0xff000000)))
//#define SEGLIMIT(d) ((d).limit0 | (((unsigned int)(d).limit1) << 16))

//VERY basic descriptor init function, sets many fields to user space sane defaults
static void init_descriptor(struct SegmentDescriptor *desc, uint32_t base, uint32_t limit, uint8_t is_code)
{
    desc->desc = 0;  //clear the descriptor
    desc->base0 = base & 0xffff;
    desc->base1 = (base >> 16) & 0xff;
    desc->base2 = base >> 24;
    if (limit > 0xfffff) {
        //need Giant granularity
        limit >>= 12;
        desc->granularity = 1;
    }
    desc->limit0 = limit & 0xffff;
    desc->limit1 = limit >> 16;

    //some sane defaults
    desc->dpl = 3;
    desc->present = 1;
    desc->db = 1;   //32 bit
    desc->type = is_code ? 0xb : 3;
    desc->system = 1;  //code or data
}

bool init_gdt(uc_engine* uc, uint32_t *fsBase)
{
    uc_err err;
    uint8_t buf[128];
    uc_x86_mmr gdtr;

    const uint64_t gdt_address = 0xc0000000;
    const uint64_t fs_address = 0x7efdd000;

	*fsBase = fs_address;

    struct SegmentDescriptor *gdt = (struct SegmentDescriptor*)calloc(31, sizeof(struct SegmentDescriptor));

    gdtr.base = gdt_address;  
    gdtr.limit = 31 * sizeof(struct SegmentDescriptor) - 1;

    //init_descriptor(&gdt[14], 0, 0xfffff000, 1);  //code segment
    //init_descriptor(&gdt[15], 0, 0xfffff000, 0);  //data segment
    init_descriptor(&gdt[16], 0x7efdd000, 0xfff, 0);  //one page data segment simulate fs
    init_descriptor(&gdt[17], 0, 0xfffff000, 0);  //ring 0 data
    gdt[17].dpl = 0;  //set descriptor privilege level

    /*
       fprintf(stderr, "GDT: \n");
       hex_dump((unsigned char*)gdt, 31 * sizeof(struct SegmentDescriptor));
     */

    // map 64k for a GDT
    err = uc_mem_map(uc, gdt_address, 0x10000, UC_PROT_WRITE | UC_PROT_READ);
    if(err != UC_ERR_OK){
		printf("failed to map in gdt address\n");
		return false;
	}

    //set up a GDT BEFORE you manipulate any segment registers
    err = uc_reg_write(uc, UC_X86_REG_GDTR, &gdtr);
   if(err != UC_ERR_OK){
		printf("failed to set gdt reg\n");
		return false;
	}

    // write gdt to be emulated to memory
    err = uc_mem_write(uc, gdt_address, gdt, 31 * sizeof(struct SegmentDescriptor));
    if(err != UC_ERR_OK){
		printf("failed to write to gdt address\n");
		return false;
	}

    // map 1 page for FS
    err = uc_mem_map(uc, fs_address, 0x1000, UC_PROT_WRITE | UC_PROT_READ);
    if(err != UC_ERR_OK){
		printf("failed to map in fs address\n");
		return false;
	}

    // when setting SS, need rpl == cpl && dpl == cpl
    // emulator starts with cpl == 0, so we need a dpl 0 descriptor and rpl 0 selector
	int r_ss = 0x88;      //ring 0
    err = uc_reg_write(uc, UC_X86_REG_SS, &r_ss);
    if(err != UC_ERR_OK){
		printf("failed to set ss register\n");
		return false;
	}

	/*
	int r_cs = 0x73;
    err = uc_reg_write(uc, UC_X86_REG_CS, &r_cs);
    if(err != UC_ERR_OK){
		printf("failed to set cs register\n");
		return false;
	}

	int r_ds = 0x7b;
    err = uc_reg_write(uc, UC_X86_REG_DS, &r_ds);
    if(err != UC_ERR_OK){
		printf("failed to set ds register\n");
		return false;
	}

	int r_es = 0x7b;
    err = uc_reg_write(uc, UC_X86_REG_ES, &r_es);
    if(err != UC_ERR_OK){
		printf("failed to set es register\n");
		return false;
	}*/

	int r_fs = 0x83;
    err = uc_reg_write(uc, UC_X86_REG_FS, &r_fs);
    if(err != UC_ERR_OK){
		printf("failed to set fs register\n");
		return false;
	}

	return true;

}
 
