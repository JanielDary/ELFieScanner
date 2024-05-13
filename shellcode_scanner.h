#ifndef SHELLCODE_SCANNER_H_
#define SHELLCODE_SCANNER_H_

#include "elf_info.h" // We have to include this, unless we want to redifine all the custom elf_info related structs here.

#include <vector>
#include <string>
#include <string.h>
#include <fstream>
#include <unistd.h>
#include <elf.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>

#define SHELLCODE_SCANNER 0x00000004


struct ss_flags 
{
    // Each flag is prepended with 'ss' referring to 'shellcode scanner'. This is to avoid confusion when one heuristics applies to multiple scanners.

    bool ss_proc_missing_disk_backing = false; // Heuristic 1 : Process missing disk backed binary. 
    bool ss_proc_phdr_memory_disk_mismatch = false; // Heuristic 2 : The number of process program headers in memory should equal that of its corresponding disk binary. Any mismatch indicates a segment has either been added or taken away in memory
    bool ss_rwx_present_disk = false; // Heuristic 3 : Process memory contains a segment with Read/write & execute permissions.
    bool ss_rwx_present_mem = false; // Heuristic 4 : Process binary contains a segment with Read/write & execute permissions.
    bool ss_dynamic_segment_missing = false; // Heuristic 5 : Dynamic segment missing. Can indicate packing. 
    bool ss_memfd_mapping_found = false; // Heuristic 6 : Process loaded directly from memory using memfd_create()

    bool ss_mod_missing_disk_backing = false; // Heuristic 7 : module missing disk backed binary. Check for all modules
    bool ss_mod_phdr_memory_disk_mismatch = false; // Heuristic 8: The number of module program headers in memory should equal that of its corresponding disk binary. Any mismatch indicates a segment has either been added or taken away in memory. Check for all modules.
    bool ss_mod_rwx_header_present_disk = false; // Heuristic 9 : Module memory contains a segment with Read/write & execute permissions. Check for all modules. 
    bool ss_mod_rwx_header_present_mem = false; // Heuristic 10 : Module binary contains a segment with Read/write & execute permissions. Check for all modules. 

    int ss_proc_score = 100; // Heuristic 11: This measures the similarity between process disk & memory text (RX) segments. A low score indicates significant changes (and thus possible injection of code).
    int ss_lowest_mod_score = 100; // Heuristic 12: This measures the similarity between module disk & memory text (RX) segments. A low score indicates significant changes (and thus possible injection of code).
};


struct module_fuzzy
{
    std::string module_path;
    uint64_t base_address;
    int mod_text_score = -1; // Default of no score.

    bool disk_backed = false;
    int mod_number_of_headers_disk = 0;
    int mod_number_of_headers_mem = 0;
    bool mod_rwx_header_present_disk = false;
    bool mod_rwx_header_present_mem = false;

    // vector<Elf64_Phdr> mod_rwxHeaders_disk;
    // vector<Elf64_Phdr> mod_rwxHeaders_mem;
};

struct shellcode_results
{
    time_t proc_start_time;
    pid_t pid;
    pid_t ppid;
    std::string hostname;
    std::string process_path;
    uint64_t base_address;
    std::string cmdline;
    bool disk_backed;
    bool memfd_anonymous_mapping_found = false;
    int proc_text_score = -1; // Default value for no score.
    int proc_number_of_headers_disk = 0;
    int proc_number_of_headers_mem = 0;
    bool process_rwx_header_present_mem = false;
    bool process_rwx_header_present_disk = false;

    bool dynamic_segment_present = true;
    std::vector<module_fuzzy> module_scores;

    // vector<Elf64_Phdr> proc_rwxHeaders_disk;
    // vector<Elf64_Phdr> proc_rwxHeaders_mem;
};

struct shellcode_thread_data_64
{
    config my_config;
    int thread_id;
    std::vector<elf_info_64> *elf_info_64_vector;
    std::vector<shellcode_results> *results_vector; // This is an overall vector for all scanners.
};

struct shellcode_thread_data_32
{
    config my_config;
    int thread_id;
    std::vector<elf_info_32> *elf_info_32_vector;
    std::vector<shellcode_results> *results_vector; // This is an overall vector for all scanners.
};


// Generic funcs
void to_json_shellcode(json &j, const shellcode_results &r);
void shellcode_results_writer(const char *name, std::vector<shellcode_results> *results_vector);

bool is_pid_up(pid_t pid);
// generate fuzzy hash, should probably be in utils too? Maybe depending on how it is implemented.
bool validate_data_64(elf_info_64 elf_info);
bool validate_data_32();
void check_shellcode_config_settings(config my_config, ss_flags my_flags, bool *add_result);


// 32-bit specific funcs
bool get_fuzzy_hash_mem_32(pid_t pid, Elf32_Addr base_vaddr, Elf32_Phdr text_pHdr_mem, std::string &fuzzy_hash, uint16_t e_type);
bool get_fuzzy_hash_disk_32(pid_t pid, std::string file_name, Elf32_Phdr text_pHdr_disk, std::string &fuzzy_hash);
void collect_shellcode_results_32(elf_info_32 elf_info_32, std::vector<shellcode_results> *shellcode_results_vector, config my_config);
void *start_shellcode_thread_32(void *threadarg);
void shellcode_scanner_main_32(elf_info_32_group *elf_info_32_pots, config my_config);


// 64-bit specific funcs
bool get_fuzzy_hash_mem_64(pid_t pid, Elf64_Addr base_vaddr, Elf64_Phdr text_pHdr_mem, std::string &fuzzy_hash, uint16_t e_type);
bool get_fuzzy_hash_disk_64(pid_t pid, std::string file_name, Elf64_Phdr text_pHdr_disk, std::string &fuzzy_hash);
void collect_shellcode_results_64(elf_info_64 elf_info_64, std::vector<shellcode_results> *shellcode_results_vector, config my_config);
void *start_shellcode_thread_64(void *threadarg);
void shellcode_scanner_main_64(elf_info_64_group *elf_info_64_pots, config my_config);

#endif