#ifndef ELF_INFO_H_
#define ELF_INFO_H_

#include <unistd.h>
#include <sys/stat.h>
#include <vector>
#include <link.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <string>
#include <fstream>
#include <iterator>
#include <elf.h>
#include <sys/utsname.h>
#include <time.h>

#include "utils.h"
#include "pmparser.h"
#include "json.hpp"

using nlohmann::json;

//////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////

// TODO : Build out this config, including shared fields.
struct config
{
	// Set any heuristic to 'true' to turn it on & start generating event for it. 

	// Entry Point scanner checks
	bool es_section_hdr_missing;			 // Heuristic 1 : Section headers can been stripped from a binary (this is suspicious but not necessarily malicious). Stripping the section headers makes reverse engineering of the binary more difficult. However it could be done make the binary smaller.
										 		// e_shoff This member holds the section header table's file offset in bytes. If the file has no section header table, this member holds zero.
	bool es_phdr_wrong_location;			 // Heuristic 2: Check to see if if the program headers start in the expected place (immediately after the ELF32_Ehdr/ELF64_Ehdr) e.g. 64 bytes offset for 64-bit, or 52 bytes offset for 32-bit.
	bool es_proc_missing_disk_backing;		 // Heuristic 3: Check the process is not backed by disk executable. More of an anomaly rather than a detection.
	bool es_proc_text_segment_missing_disk; // Heuristic 4: Check to see if the .text segment is present on disk. This should always be present unless the binary is still packed/obfuscated in memory.
	bool es_proc_text_segment_missing_mem;	 // Heuristic 5: Is the .text segment is present in memory. This should always be present unless the disk backed binary is packed/obfuscated.
	bool es_proc_entry_points_not_in_text;	 // Heuristic 6: Check to see if the e_entry field does NOT point within the .text segment. This should always be the case apart from special cases such as ‘VBoxService’.
	bool es_proc_entry_points_not_matching; // Heuristic 7: Check to see if the e_entry values for process & disk binary match.
	int es_proc_entry_fuzzy_score = 100;	 // Heuristic 8: Check the e_entry for the libc linked process matches the expected initialization code for ‘libc_start_main’. Highly suspicious unless this is for an interpreter process e.g. ‘/usr/bin/python’ OR container processes ‘/usr/sbin/VBoxService’
												// If real score is below es_proc_entry_fuzzy_score then result will be generated. 

	bool es_proc_init_fini_not_in_text; // Heuristic 9:
									 		// process init/fini sections that don't appear in .text segment
									 		// process preinit/init/fini array functions that don't point within the .text segment.

	bool es_proc_init_not_at_text_start; // Heuristic 10: For processes it is expected the .init code block should begin at the start of the .text segment. NOTE: this is not expected for modules.

	bool es_mod_missing_disk_backing;		// Heuristic 11: Check to see if module is backed by disk executable. More of an anomaly rather than a detection. Check against every module.
	bool es_mod_entry_points_not_in_text;	// Heuristic 12: Check the e_entry field points within .text segment of the module. This should always be the case for modules. Check against every module
	bool es_mod_entry_points_not_matching; // Heuristic 13: Check to see the e_entry values for module and disk match. Check against every module.

	bool es_mod_init_fini_not_in_text; // Heuristic 14:
											// module init/fini sections that don't appear in .text segment
											// module preinit/init/fini array functions that don't point within the .text segment.
											// Checks against every module.

	// Library scanner checks.
	bool ls_elf_in_anonymous_mapping;	   // Heuristic 1 : ELF header found in anonymous memory mapping
	bool ls_executable_anonymous_mapping; // Heuristic 2 : Executable anonymous memory mapping
	bool ls_phdr_wrong_location;		   // Heuristic 3: Program headers wrong location.
	bool ls_mod_missing_disk_backing;   	// Heuristic 4 : Module doesn't have disk backing. Checks for every module.
	bool ls_module_not_in_procmaps;	   		// Heuristic 5: Module doesn't exist in /proc/<pid>/maps. Checks for every module.
	bool ls_module_not_in_linkmap;		   // Heuristic 6: Module doesn't exist in link_map structure. Checks for every module.
	bool ls__libc_dlopen_mode_in_got;	   // Heuristic 7: GOT address points __libc_dlopen_mode func.
	bool ls__libc_dlopen_mode_in_rodata; // Heuristic 8: __libc_dlopen_mode string in rodata section.
	bool ls_dtnull_missing;			   		// Heuristic 9 : DT_NULL missing from dynamic section.
	bool ls_dtdebug_missing;			   // Heuristic 10: DT_DEBUG missing from dynamic section
	bool ls_dtneeded_incorrect_order;	   // Heuristic 11: DT_NEEDED in non-sequential (incorrect) order in dynamic section
	bool ls_dynstr_manipulated;		   		// Heuristic 12: Dynamic string table manually manipulated
	bool ls_ldpreload_set;				   // Heuristic 13: LD_PRELOAD populated
	bool ls_ldpreload_hooking;			   // Heuristic 14: LD_PRELOAD hooking present
	bool ls_ldconfig_set;				   // Heuristic 15: LD_CONFIG populated
	bool ls_ldpath_set;				   		// Heuristic 16: LD_PATH manipulated
	bool ls_dynamic_segment_missing;	   // Heuristic 17: Dynamic segment missing

	// Shellcode scanner checks
	bool ss_proc_missing_disk_backing;		 // Heuristic 1 : Process missing disk backed binary.
	bool ss_proc_phdr_memory_disk_mismatch; // Heuristic 2 : The number of process program headers in memory should equal that of its corresponding disk binary. Any mismatch indicates a segment has either been added or taken away in memory
	bool ss_rwx_present_disk;				 // Heuristic 3 : Process memory contains a segment with Read/write & execute permissions.
	bool ss_rwx_present_mem;				 // Heuristic 4 : Process binary contains a segment with Read/write & execute permissions.
	bool ss_dynamic_segment_missing;		 // Heuristic 5 : Dynamic segment missing. Can indicate packing.
	bool ss_memfd_mapping_found;			 // Heuristic 6 : Process loaded directly from memory using memfd_create()
	bool ss_mod_missing_disk_backing;		 // Heuristic 7 : module missing disk backed binary. Check for all modules
	bool ss_mod_phdr_memory_disk_mismatch;	 // Heuristic 8: The number of module program headers in memory should equal that of its corresponding disk binary. Any mismatch indicates a segment has either been added or taken away in memory. Check for all modules.
	bool ss_mod_rwx_header_present_disk;	 // Heuristic 9 : Module memory contains a segment with Read/write & execute permissions. Check for all modules.
	bool ss_mod_rwx_header_present_mem;	 	// Heuristic 10 : Module binary contains a segment with Read/write & execute permissions. Check for all modules.
	int ss_proc_score = 100;				// Heuristic 11: This measures the similarity between process disk & memory text (RX) segments. A low score indicates significant changes (and thus possible injection of code).
	int ss_lowest_mod_score = 100;			// Heuristic 12: This measures the similarity between module disk & memory text (RX) segments. A low score indicates significant changes (and thus possible injection of code).
												// If real score is below ss_proc_score/ss_lowest_mod_score then result will be generated.
};

struct custom_link_map_64
{
	Elf64_Addr l_addr;				  // Difference between the address in the ELF file and the addresses in memory.
	char *l_name;					  // Absolute file name object was found in.
	Elf64_Dyn *l_ld;				  // Dynamic section of the shared object.
	struct link_map *l_next, *l_prev; // Chain of loaded objects.
	std::string library_name;
};

struct r_debug_32
{
	int r_version; /* Version number for this protocol.  */

	Elf32_Addr r_map; /* Head of the chain of loaded objects.  */

	/* This is the address of a function internal to the run-time linker,
	   that will always be called when the linker begins to map in a
	   library or unmap it, and again when the mapping change is complete.
	   The debugger can set a breakpoint at this address if it wants to
	   notice shared object mapping changes.  */
	Elf32_Addr r_brk;
	enum
	{
		/* This state value describes the mapping change taking place when
	   the `r_brk' address is called.  */
		RT_CONSISTENT, /* Mapping change is complete.  */
		RT_ADD,		   /* Beginning to add a new object.  */
		RT_DELETE	   /* Beginning to remove an object mapping.  */
	} r_state;

	Elf32_Addr r_ldbase; /* Base address the linker is loaded at.  */
};

struct custom_link_map_32
{
	Elf32_Addr l_addr; // Difference between the address in the ELF file and the addresses in memory.
	Elf32_Addr l_name; // Absolute file name object was found in.
	Elf32_Addr l_ld;   // Dynamic section of the shared object.
	Elf32_Addr l_next;
	Elf32_Addr l_prev; // Chain of loaded objects.
	std::string library_name;
};

struct link_map_32
{
	Elf32_Addr l_addr; // Difference between the address in the ELF file and the addresses in memory.
	Elf32_Addr l_name; // Absolute file name object was found in.
	Elf32_Addr l_ld;   // Dynamic section of the shared object.
	Elf32_Addr l_next; // Next loaded shared object.
	Elf32_Addr l_prev; // Previous loaded shared object.
};

typedef struct single_procmap_struct
{
	void *addr_start;
	void *addr_end;
	unsigned long length;

	char perm[5];
	short is_r;
	short is_w;
	short is_x;
	short is_p;

	long offset;
	char dev[12];
	int inode;

	char pathname[600];
} single_procmap_struct;

struct stack_vars
{
	bool ld_preload_present = false;
	std::string ld_preload;
	bool ld_path_present = false;
	std::string ld_path;
	bool ld_config_present = false;
	std::string ld_config;
};

struct auxv_phdr_info
{
	uint64_t phdr_addr;	 // Program header table address
	uint64_t phdr_sz;	 // Program header table size in bytes
	uint64_t phdr_count; // Number of program headers
};

struct dt_needed_entries
{
	uint32_t index_into_dt_strtab; // The DT_STRTAB (Dynamic string table) offset of a null-terminated string, giving the name of a needed dependency. String table is small hence uint32 is big enough for both 32 & 64-bit.
	std::string module_name;	   // Module name from DT_STRTAB (Dynamic string table)
	int dt_needed_index;		   // Index the entry appears in dynamic section
	bool name_in_dynstr = true;	   // Does module name appear within original confines of DT_STRTAB (Dynamic string table)
};

struct got_value_64 // Information about a global offset table entry.
{
	int GOT_entry_number;			   // Entry number in GOT
	Elf64_Addr vaddr_of_entry;		   // virtual address where entry exists
	Elf64_Addr func_pointer;		   // The GOT entry itself (a function pointer)
	Elf64_Addr vaddr_of_reloc;		   // Get this from relocation table, must match with vaddr_of_entry.
	std::string legit_reloc_func_name; // Get this from relocation table.
};

struct got_value_32 // Information about a global offset table entry.
{
	int GOT_entry_number;			   // Entry number in GOT
	Elf32_Addr vaddr_of_entry;		   // virtual address where entry exists
	Elf32_Addr func_pointer;		   // The GOT entry itself (a function pointer)
	Elf32_Addr vaddr_of_reloc;		   // Get this from relocation table, must match with vaddr_of_entry.
	std::string legit_reloc_func_name; // Get this from relocation table.
};

// We don't have to change the ElfW() types for this. As ElfW() will set to either 64/32 depending on the operating system the tools is running on NOT what type of process it is interrogating.
struct dynamic_info64
{
	bool dt_null_present = false;

	bool dt_pltgot_present = false;
	ElfW(Addr) dt_pltgot; // Start of the plt.got table

	bool dt_jmprel_present = false;
	ElfW(Addr) dt_jmprel; // Address of relocation entries associated solely with the procedure linkage table

	bool dt_pltrel_present = false;
	ElfW(Word) dt_pltrel; // type of relocation entry to which the procedure linkage table refers, either DT_REL or DT_RELA

	bool dt_pltrelsz_present = false;
	ElfW(Word) dt_pltrelsz;						// Total size in bytes of plt.got
	int got_entries = 0;						// The number of entries in the global offset table. (Including the first three reserved entries)
	std::vector<got_value_64> got_value_vector; // Information about every global offset table entry
	ElfW(Addr) link_map_got;					// The virtual address of the link_map structure, acquired from GOT[1]
	std::vector<custom_link_map_64> link_map;	// Link map, which includes base addresses of every loaded module.

	bool dt_strtab_present = false;
	bool dt_strtab_manipulated = false; // Has the the DT_STRTAB (Dynamic string table) been manipulated
	ElfW(Addr) dt_strtab;				// The address of the DT_STRTAB (Dynamic string table)

	bool dt_symtab_present = false;
	ElfW(Addr) dt_symtab; // The address of the symbol table

	bool dt_syment_present = false;
	ElfW(Word) dt_syment; // The size, in bytes, of the DT_SYMTAB symbol entry

	bool dt_strsz_present = false;
	ElfW(Word) dt_strsz; // The total size, in bytes, of the DT_STRTAB (Dynamic string table)

	bool dt_needed_present = false;
	bool dt_needed_wrong_order = false;
	std::vector<dt_needed_entries> dt_needed_indexes_vector; // Vector of all DT_NEEDED entries in a process

	bool dt_debug_present = false;
	ElfW(Addr) dt_debug; // Debug section address; used to find the link_map structure

	bool dt_hash_present = false;
	ElfW(Addr) dt_hash; // The address of the symbol hash table

	bool dt_gnu_hash_present = false;
	ElfW(Addr) dt_gnu_hash; // The address of the GNU symbol hash table

	///////////////////////////////////
	// Entry point specific sections //
	///////////////////////////////////

	bool dt_preinit_array_present = false;
	ElfW(Addr) dt_preinit_array; // The address of an array of pointers to pre-initialization functions

	bool dt_preinit_arraysz_present = false;
	ElfW(Word) dt_preinit_arraysz; // The total size, in bytes, of the DT_PREINIT_ARRAY array
	int preinit_array_func_count;  // Number of preinit_array functions

	bool dt_init_present = false;
	ElfW(Addr) dt_init; // The address of an initialization function

	bool dt_init_array_present = false;
	ElfW(Addr) dt_init_array; // The address of an array of pointers to initialization functions

	bool dt_init_arraysz_present = false;
	ElfW(Word) dt_init_arraysz; // The total size, in bytes, of the DT_INIT_ARRAY array
	int init_array_func_count;	// Number of init_array functions

	bool dt_fini_present = false;
	ElfW(Addr) dt_fini; // The address of a termination function

	bool dt_fini_array_present = false;
	ElfW(Addr) dt_fini_array; // The address of an array of pointers to termination functions

	bool dt_fini_arraysz_present = false;
	ElfW(Word) dt_fini_arraysz; // The total size, in bytes, of the DT_FINI_ARRAY array
	int fini_array_func_count;	// Number of fini_array functions
};

// For 32-bit we do have to change all ElfW -> Elf32. Because this resolved by the OS arch not the process that is being interrogating.
struct dynamic_info32
{
	bool dt_null_present = false;

	bool dt_pltgot_present = false;
	Elf32_Addr dt_pltgot; // Start of the plt.got table

	bool dt_jmprel_present = false;
	Elf32_Addr dt_jmprel; // Address of relocation entries associated solely with the procedure linkage table

	bool dt_pltrel_present = false;
	Elf32_Word dt_pltrel; // type of relocation entry to which the procedure linkage table refers, either DT_REL or DT_RELA

	bool dt_pltrelsz_present = false;
	Elf32_Word dt_pltrelsz;						// Total size in bytes of plt.got
	int got_entries = 0;						// The number of entries in the global offset table. (Including the first three reserved entries)
	std::vector<got_value_32> got_value_vector; // Information about every global offset table entry
	Elf32_Addr link_map_got;					// The virtual address of the link_map structure, acquired from GOT[1]
	std::vector<custom_link_map_32> link_map;	// Link map, which includes base addresses of every loaded module.

	bool dt_strtab_present = false;
	bool dt_strtab_manipulated = false; // Has the the DT_STRTAB (Dynamic string table) been manipulated
	Elf32_Addr dt_strtab;				// The address of the DT_STRTAB (Dynamic string table)

	bool dt_symtab_present = false;
	Elf32_Addr dt_symtab; // The address of the symbol table

	bool dt_syment_present = false;
	Elf32_Word dt_syment; // The size, in bytes, of the DT_SYMTAB symbol entry

	bool dt_strsz_present = false;
	Elf32_Word dt_strsz; // The total size, in bytes, of the DT_STRTAB (Dynamic string table)

	bool dt_needed_present = false;
	bool dt_needed_wrong_order = false;
	std::vector<dt_needed_entries> dt_needed_indexes_vector; // Vector of all DT_NEEDED entries in a process

	bool dt_debug_present = false;
	Elf32_Addr dt_debug; // Debug section address; used to find the link_map structure

	bool dt_hash_present = false;
	Elf32_Addr dt_hash; // The address of the symbol hash table

	bool dt_gnu_hash_present = false;
	Elf32_Addr dt_gnu_hash; // The address of the GNU symbol hash table

	///////////////////////////////////
	// Entry point specific sections //
	///////////////////////////////////

	bool dt_preinit_array_present = false;
	Elf32_Addr dt_preinit_array; // The address of an array of pointers to pre-initialization functions

	bool dt_preinit_arraysz_present = false;
	Elf32_Word dt_preinit_arraysz; // The total size, in bytes, of the DT_PREINIT_ARRAY array
	int preinit_array_func_count;  // Number of preinit_array functions

	bool dt_init_present = false;
	Elf32_Addr dt_init; // The address of an initialization function

	bool dt_init_array_present = false;
	Elf32_Addr dt_init_array; // The address of an array of pointers to initialization functions

	bool dt_init_arraysz_present = false;
	Elf32_Word dt_init_arraysz; // The total size, in bytes, of the DT_INIT_ARRAY array
	int init_array_func_count;	// Number of init_array functions

	bool dt_fini_present = false;
	Elf32_Addr dt_fini; // The address of a termination function

	bool dt_fini_array_present = false;
	Elf32_Addr dt_fini_array; // The address of an array of pointers to termination functions

	bool dt_fini_arraysz_present = false;
	Elf32_Word dt_fini_arraysz; // The total size, in bytes, of the DT_FINI_ARRAY array
	int fini_array_func_count;	// Number of fini_array functions
};

struct elf_mem_hdrs_64
{
	Elf64_Ehdr ehdr_mem;							// executable header
	bool phdr_irregular_location_mem = false;		// Does the program header table exist somewhere that isn't immediately after the executable header?
	bool text_pHdr_mem_present = false;				// Is the text segment present
	Elf64_Phdr text_pHdr_mem;						// text segment program header
	Elf64_Phdr data_pHdr_mem;						// data segment program header
	Elf64_Phdr dyn_pHdr_mem;						// dynamic segment program header
	Elf64_Phdr rodata_pHdr_mem;						// Segment that contains .rodata section.
	bool rwx_or_wx_header_present_mem = false;		// Any there program headers with rwx/wx permissions
	std::vector<Elf64_Phdr> rwx_and_wx_headers_mem; // Any program headers with rwx/wx permissions

	// Dynamic segment info.
	bool dynamic_segment_present = false; // Is the dynamic segment present in memory
	dynamic_info64 dyn_info_mem;		  // Dynamic segment information from memory
};

struct elf_mem_hdrs_32
{
	Elf32_Ehdr ehdr_mem;							// executable header
	bool phdr_irregular_location_mem = false;		// Does the program header table exist somewhere that isn't immediately after the executable header?
	bool text_pHdr_mem_present = false;				// Is the text segment present
	Elf32_Phdr text_pHdr_mem;						// text segment program header
	Elf32_Phdr data_pHdr_mem;						// data segment program header
	Elf32_Phdr dyn_pHdr_mem;						// dynamic segment program header
	Elf32_Phdr rodata_pHdr_mem;						// Segment that contains .rodata section.
	bool rwx_or_wx_header_present_mem = false;		// Any there program headers with rwx/wx permissions
	std::vector<Elf32_Phdr> rwx_and_wx_headers_mem; // Any program headers with rwx/wx permissions

	// Dynamic segment info.
	bool dynamic_segment_present = false; // Is the dynamic segment present in memory
	dynamic_info32 dyn_info_mem;		  // Dynamic segment information from memory
};

struct elf_disk_hrds_64
{
	Elf64_Ehdr ehdr_disk;							 // executable header
	bool phdr_irregular_location_disk = false;		 // Does the program header table exist somewhere that isn't immediately after the executable header?
	bool text_pHdr_disk_present = false;			 // Is the text segment present
	Elf64_Phdr text_pHdr_disk;						 // text segment program header
	Elf64_Phdr data_pHdr_disk;						 // data segment program header
	bool rwx_or_wx_header_present_disk = false;		 // Any there program headers with rwx/wx permissions
	std::vector<Elf64_Phdr> rwx_and_wx_headers_disk; // Any program headers with rwx/wx permissions
};

struct elf_disk_hrds_32
{
	Elf32_Ehdr ehdr_disk;							 // executable header
	bool phdr_irregular_location_disk = false;		 // Does the program header table exist somewhere that isn't immediately after the executable header?
	bool text_pHdr_disk_present = false;			 // Is the text segment present
	Elf32_Phdr text_pHdr_disk;						 // text segment program header
	Elf32_Phdr data_pHdr_disk;						 // data segment program header
	bool rwx_or_wx_header_present_disk = false;		 // Any there program headers with rwx/wx permissions
	std::vector<Elf32_Phdr> rwx_and_wx_headers_disk; // Any program headers with rwx/wx permissions
};

struct elf_modules_64
{
	bool disk_backed = true;
	std::string module_path;
	Elf64_Addr base_vaddr;
	elf_mem_hdrs_64 elf_mem_hdrs;
	elf_disk_hrds_64 elf_disk_hrds;
};

struct elf_modules_32
{
	bool disk_backed = true;
	std::string module_path;
	Elf32_Addr base_vaddr;
	elf_mem_hdrs_32 elf_mem_hdrs;
	elf_disk_hrds_32 elf_disk_hrds;
};

struct elf_info_64
{
	/////////////////////
	// Process details //
	/////////////////////

	time_t proc_start_time;								 // process start time
	pid_t pid;											 // process id
	pid_t ppid;											 // parent process id
	std::string hostname;								 // Hostname of system
	std::string process_path;							 // Full path of process and name
	std::string cmdline;								 // Command line used to launch process
	Elf64_Addr base_vaddr;								 // Base address of process in memory
	std::vector<single_procmap_struct> proc_maps_vector; // proc/<pid>/maps for the process
	bool disk_backed = true;							 // Is the process backed by a disk binary
	bool memfd_anonymous_mapping_found = false;			 // Was the process launched using memfd_create()
	auxv_phdr_info auxv_phdr_data;						 // Program header table info from the auxilary vector
	stack_vars stack_variables;							 // LD_PRELOAD, LD_CONFIG and LD_LIBRARY_PATH values from the stack.

	//////////////////////////
	// ELF - Memory Headers //
	//////////////////////////

	elf_mem_hdrs_64 elf_mem_hdrs;

	////////////////////////////
	// Dynamic info - Memory ///
	////////////////////////////

	////////////////////////
	// ELF - Disk Headers //
	////////////////////////

	elf_disk_hrds_64 elf_disk_hdrs;

	/////////////////////////
	// ELF -Loaded modules //
	/////////////////////////

	std::vector<elf_modules_64> elf_modules;
	bool libc_present = false;
};

struct elf_info_32
{
	/////////////////////
	// Process details //
	/////////////////////

	time_t proc_start_time;								 // process start time
	pid_t pid;											 // process id
	pid_t ppid;											 // parent process id
	std::string hostname;								 // Hostname of system
	std::string process_path;							 // Full path of process and name
	std::string cmdline;								 // Command line used to launch process
	Elf32_Addr base_vaddr;								 // Base address of process in memory
	std::vector<single_procmap_struct> proc_maps_vector; // proc/<pid>/maps for the process
	bool disk_backed = true;							 // Is the process backed by a disk binary
	bool memfd_anonymous_mapping_found = false;			 // Was the process launched using memfd_create()
	auxv_phdr_info auxv_phdr_data;						 // Program header table info from the auxilary vector
	stack_vars stack_variables;							 // LD_PRELOAD, LD_CONFIG and LD_LIBRARY_PATH values from the stack.

	//////////////////////////
	// ELF - Memory Headers //
	//////////////////////////

	elf_mem_hdrs_32 elf_mem_hdrs;

	////////////////////////////
	// Dynamic info - Memory ///
	////////////////////////////

	////////////////////////
	// ELF - Disk Headers //
	////////////////////////

	elf_disk_hrds_32 elf_disk_hdrs;

	/////////////////////////
	// ELF -Loaded modules //
	/////////////////////////

	std::vector<elf_modules_32> elf_modules;
	bool libc_present = false;
};

struct elf_info_64_group
{
	std::vector<elf_info_64> elf_info_64_pots[THREAD_COUNT];
};

struct elf_info_32_group
{
	std::vector<elf_info_32> elf_info_32_pots[THREAD_COUNT];
};

struct elf_info_thread_data_64
{
	config my_config;
	std::vector<pid_t> pid_group;
	std::vector<elf_info_64> *elf_info_64_vector;
	int thread_id;
};

struct elf_info_thread_data_32
{
	std::vector<pid_t> pid_group;
	std::vector<elf_info_32> *elf_info_32_vector;
	int thread_id;
};

///////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////

// Generic
bool read_config(char *config_path, config *my_config);
bool collect_maps(pid_t pid, std::vector<single_procmap_struct> *proc_maps_vector);
bool get_stack_values(int pid, std::vector<single_procmap_struct> *proc_maps_vector, stack_vars *stack_vars);

// 64-bit specific
void resolve_dt_needed_names_64(pid_t pid, dynamic_info64 *dyn_info);
void generate_elf_info_64_pots(std::vector<elf_info_64> *elf_info_vector, elf_info_64_group *elf_info_groups);
bool get_auxv64(elf_info_64 *elf);
bool get_headers_and_segment_info_mem_64(pid_t pid, Elf64_Addr base_vaddr, elf_mem_hdrs_64 *elf_mem_hdrs);
bool get_headers_and_segment_info_disk_64(pid_t pid, std::string file_name, elf_disk_hrds_64 *elf_disk_hdrs, bool *disk_backed);
bool get_dynamic_info_64(pid_t pid, Elf64_Addr base_vaddr, Elf64_Ehdr ehdr_mem, Elf64_Phdr dyn_pHdr_mem, dynamic_info64 *dyn_info_mem);
bool get_got_64(pid_t pid, dynamic_info64 dyn_info, std::vector<got_value_64> *got_value_vector, ElfW(Addr) * link_map_got);
bool get_link_map_64(pid_t pid, dynamic_info64 *dyn_info);
void collect_results64(pid_t pid, std::vector<elf_info_64> *elf_info_64_vector);
void *start_elf_info_thread_64(void *threadarg);
void elf_info_main_64(std::vector<elf_info_64> *elf_info_64_vector, pid_group pidPots);

// 32-bit specific
void generate_elf_info_32_pots(std::vector<elf_info_32> *elf_info_vector, elf_info_32_group *elf_info_groups);
void resolve_dt_needed_names_32(pid_t pid, dynamic_info32 *dyn_info);
bool get_headers_and_segment_info_mem_32(pid_t pid, Elf32_Addr base_vaddr, elf_mem_hdrs_32 *elf_mem_hdrs);
bool get_headers_and_segment_info_disk_32(pid_t pid, std::string file_name, elf_disk_hrds_32 *elf_disk_hdrs, bool *disk_backed);
bool get_auxv32(elf_info_32 *elf);
bool get_dynamic_info_32(pid_t pid, Elf32_Addr base_vaddr, Elf32_Ehdr ehdr_mem, Elf32_Phdr dyn_pHdr_mem, dynamic_info32 *dyn_info_mem);
bool get_got_32(pid_t pid, dynamic_info32 dyn_info, std::vector<got_value_32> *got_value_vector, Elf32_Addr *link_map_got);
bool get_link_map_32(pid_t pid, dynamic_info32 *dyn_info);
void collect_results32(pid_t pid, std::vector<elf_info_32> *elf_info_32_vector);
void *start_elf_info_thread_32(void *threadarg);
void elf_info_main_32(std::vector<elf_info_32> *elf_info_64_vector, pid_group pidPots);

#endif