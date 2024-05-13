#ifndef UTILS_H_
#define UTILS_H_

#include <unistd.h>
#include <string>
#include <string.h> // for strerror
#include <vector>
#include <elf.h>
#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <fnmatch.h>
#include <sys/uio.h>
#include <fuzzy.h> // part of ssdeep libraries.
#include <iostream>
#include <cmath> // for ciel. 
#include <random> // for shuffle pids
#include <sys/utsname.h> // for utsname & systeminfo

#define PAGESIZE sysconf(_SC_PAGESIZE)
#define MAX_PATH 4096
#define WHITE_LIST_SIZE 4
#define THREAD_COUNT 8
#define THREAD_POLICY SCHED_IDLE
#define NUM_CPUS 1

const char *const whitelist[WHITE_LIST_SIZE]{
	"/gdb",
	"/snap/code/",
	"/.vscode/",
	"/.vscode-server/"};

struct page_boundaries
{
    size_t page_sz;
    uint64_t next_page_addr;
    uint64_t previous_page_addr;
    uint64_t bytes_to_next_page;
    uint64_t bytes_into_page;
};

struct pid_group
{
	std::vector<pid_t> pid_pots[THREAD_COUNT];
};

template <typename T>
inline bool contains(std::vector<T> vec, const T &elem)
{
    bool result = false;
    if (find(vec.begin(), vec.end(), elem) != vec.end())
    {
        result = true;
    }
    return result;
}


void print_help(char *name);
void set_cpu_affinity(pthread_t *main_thread);
bool is_whitelisted(pid_t pid);
bool check_arch(pid_t pid, bool *is_64_bit, bool *is_32_bit);
std::vector<pid_t> filter_pids(std::vector<pid_t> *pids);
void generate_pid_pots(std::vector<pid_t> pids, pid_group *pid_groups);
void split_pids_into_32_64(std::vector<pid_t> *pids_64, std::vector<pid_t> *pids_32, std::vector<pid_t> pids);
std::string sanitize_string(std::string &s);
void get_page_boundaries(uint64_t address, page_boundaries *pBoundaries);
bool exists(const std::string &name);
void processdir(const struct dirent *dir, std::vector<pid_t> *pids);
int filter(const struct dirent *dir);
void get_process_start_time(pid_t pid, time_t *startTime);
void get_pids(std::vector<pid_t> *pids);
std::string get_process_path(pid_t pid);
pid_t get_ppid(pid_t pid);
std::string get_process_cmdline(const int pid);
int process_read(int pid, void *dst, const void *src, size_t len);
uint64_t get_proc_base(pid_t pid);
std::string get_mod_name(pid_t pid, Elf64_Addr nameAddr);
void get_fuzzy_hash_score(const char *mem, const char *disk, int *score);

#endif