// Common functions

#include "utils.h"

void set_cpu_affinity(pthread_t *main_thread)
{
	cpu_set_t *cpu_set;
	size_t cpu_size;

	// Allocate a CPU set large enough to hold CPUs in the range 0 to num_cpus-1.
	cpu_set = CPU_ALLOC(NUM_CPUS);
	if (cpu_set == NULL)
	{
		printf("Unable to allocate CPU set\n");
		exit(EXIT_FAILURE);
	}

	// Return the size in bytes of the CPU set that would be needed to hold CPUs in the range 0 to num_cpus-1.
	cpu_size = CPU_ALLOC_SIZE(NUM_CPUS);

	// Clear cpu_set.
	CPU_ZERO_S(cpu_size, cpu_set);

	// Sets cpu_set to use cpu 0. i.e the first CPU.
	CPU_SET_S(0, cpu_size, cpu_set);

	// Set main process thread to use cpu_set. In this case CPU 0.
	if (pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), cpu_set))
	{
		printf("Error: unable to set cpu_set using pthread_setaffinity_np\n");
		exit(EXIT_FAILURE);
	}

	// Print Message if CPU is successfully set
	if (CPU_ISSET_S(0, sizeof(cpu_set_t), cpu_set))
		printf("proc_scanner set to use CPU:%d\n", 0);

	CPU_FREE(cpu_set);
}

bool is_whitelisted(pid_t pid, bool *whiteListed)
{
	char maps[MAX_PATH], line[256];
	char *pch, *ret;
	int i;
	FILE *fd;

	snprintf(maps, MAX_PATH - 1, "/proc/%d/maps", pid);

	if ((fd = fopen(maps, "r")) == NULL)
	{
		fprintf(stderr, "Cannot open %s for reading: %s\n", maps, strerror(errno));
		return false;
	}

	while (fgets(line, sizeof(line), fd))
	{
		ret = strstr(line, "p ");
		ret = strstr(line, "/");
		if (ret == nullptr)
			continue;
		for (i = 0; i < WHITE_LIST_SIZE; i++)
		{
			pch = strstr(line, whitelist[i]);
			if (pch != NULL)
			{
				*whiteListed = true;
				break;
			}
		}
		break;
	}
	fclose(fd);
	return true;
}

bool check_arch(pid_t pid, bool *is_64_bit, bool *is_32_bit)
{
	uint64_t base_vaddr;
	uint16_t e_type;
	unsigned char e_ident[16];

	base_vaddr = get_proc_base(pid);

	if (process_read(pid, (void *)&e_ident, (void *)base_vaddr, 16) == -1)
	{
		printf("Failed to read e_ident with process_read() in function check_arch: %s from pid: %i\n", strerror(errno), pid);
		return false;
	}

	// Check to see if this is an ELF process
	if ((e_ident[0] != 0x7f) && (e_ident[1] != 0x45) && (e_ident[2] != 0x4c) && (e_ident[3] != 0x46))
	{
		printf("Process is not an ELF process. Pid: %i. In function 'check_arch'\n", pid);
		return false;
	}

	// Check to see if it is running in as 32/64 bit.
	if (e_ident[4] == 2)
	{
		*is_64_bit = true;
	}
	else if (e_ident[4] == 1)
	{
		*is_32_bit = true;
	}
	else
	{
		// We should never get here;
		printf("Unidentified arch type. Pid: %i. In function 'check_arch'\n", pid);
		return false;
	}

	return true;
}

std::vector<pid_t> filter_pids(std::vector<pid_t> *pids)
{
	bool inWhiteList;
	pid_t currentPid = getpid();
	pid_t parent_pid;
	std::vector<pid_t> filtered_pids;

	for (auto it = pids->begin(); it != pids->end(); ++it)
	{
		inWhiteList = false;
		parent_pid = get_ppid((*it));

		// Do not scan ourselves, the main kernel thread (pid == 2) & it's children.
		if (((*it) != currentPid) && ((*it) != 2) && (parent_pid != 2))
		{
			if (!is_whitelisted((*it), &inWhiteList))
				continue; // If pid is whitelisted then don't include in list.

			if (!inWhiteList)
			{
				filtered_pids.push_back(*it);
			}
		}
	}

	return filtered_pids;
}

void generate_pid_pots(std::vector<pid_t> pids, pid_group *pid_groups)
{
	int size;
	int i = 0;
	int counter = 0;

	// Split into pots determined by number of threads.
	size = pids.size();

	double float_potSize = (double)size / THREAD_COUNT;
	int potSize = ceil(float_potSize); // Round up so we don't create more pots than threads.

	for (auto it = pids.begin(); it != pids.end(); ++it)
	{

		if (counter < potSize)
		{
			pid_groups->pid_pots[i].push_back(*it);
			counter++;
			continue;
		}
		else if (counter % potSize == 0)
		{
			i++; // Start a new group
		}

		pid_groups->pid_pots[i].push_back(*it);
		counter++;
	}
}

void split_pids_into_32_64(std::vector<pid_t> *pids_64, std::vector<pid_t> *pids_32, std::vector<pid_t> pids)
{
	for (auto it = pids.begin(); it != pids.end(); ++it)
	{
		bool is_64_bit = false;
		bool is_32_bit = false;

		if (!check_arch((*it), &is_64_bit, &is_32_bit))
		{
			printf("Invalid process pid: %i", (*it));
			continue;
		}

		if (is_64_bit)
			pids_64->push_back((*it));
		else if (is_32_bit)
			pids_32->push_back((*it));
	}
}



std::string sanitize_string(std::string &s)
{
	std::string sanitized_string;

	// 32 - 126
	for (auto it = s.cbegin(); it != s.cend(); ++it)
	{
		if ((*it < 32) || (*it > 126))
			sanitized_string.push_back('?');
		else
			sanitized_string.push_back(*it);
	}

	return sanitized_string;
}

void get_page_boundaries(uint64_t address, page_boundaries *pBoundaries)
{
	pBoundaries->page_sz = PAGESIZE;
	pBoundaries->bytes_into_page = address % pBoundaries->page_sz;
	pBoundaries->bytes_to_next_page = pBoundaries->page_sz - pBoundaries->bytes_into_page;
	pBoundaries->previous_page_addr = address - pBoundaries->bytes_into_page;
	pBoundaries->next_page_addr = address + pBoundaries->bytes_to_next_page;
}


bool exists(const std::string &name)
{
	struct stat buffer;
	return (stat(name.c_str(), &buffer) == 0);
}

void processdir(const struct dirent *dir, std::vector<pid_t> *pids)
{
	pid_t pid = atoi(dir->d_name);
	pids->push_back(pid);
}

int filter(const struct dirent *dir)
{
	return !fnmatch("[1-9]*", dir->d_name, 0);
}

void get_process_start_time(pid_t pid, time_t *startTime)
{
	// Correct way of doing this would be to get current time
	// gettimeofday()
	// Then get uptime from /proc/uptime - boot_time
	// Then get process_start_time (value in jiffies) from /proc/<pid>/stat.

	// This is a cheat way assuming the /proc/<pid>/cmdline is created when process is launched and doesn't change during execution (which it shouldn't!)
	// I imagine this code will be completely rewritten anyway :)

	struct stat sb;
	int size;
	char buffer[100];
	size = snprintf(buffer, 100, "/proc/%i/cmdline", pid);

	if (size)
	{
		stat(buffer, &sb);
		*startTime = sb.st_mtime;
	}
	else
	{
		printf("Unable to get process start time for pid: %i\n", pid);
	}
}

void get_pids(std::vector<pid_t> *pids)
{
	struct dirent **namelist;
	int n;

	n = scandir("/proc", &namelist, filter, 0);
	if (n < 0)
		perror("Not enough memory.");
	else
		while (n--)
		{
			processdir(namelist[n], pids);
			free(namelist[n]);
		}
	free(namelist);
}

// Get process path from /proc/%d/exe using readlink()
std::string get_process_path(pid_t pid)
{
	char *procExeDir = (char *)alloca(512);
	sprintf(procExeDir, "/proc/%d/exe", pid);
	std::string result;

	char *name = (char *)calloc(1, MAX_PATH);
	if (name)
	{
		if (readlink(procExeDir, name, MAX_PATH - 1) == -1)
		{
			printf("Unable to get process path for pid: %i", pid);
		}
	}

	result = name;
	free(name);

	return sanitize_string(result);
}

pid_t get_ppid(pid_t pid)
{
	char status[MAX_PATH], line[256];
	char *start, *p;
	FILE *fd;
	int i;
	pid_t ppid;

	snprintf(status, MAX_PATH - 1, "/proc/%d/status", pid);

	if ((fd = fopen(status, "r")) == NULL)
	{
		printf("Cannot open %s for reading: %s\n", status, strerror(errno));
		return -1;
	}

	while (fgets(line, sizeof(line), fd))
	{
		if (!strstr(line, "PPid:"))
			continue;
		for (i = 0, start = (char *)alloca(32), p = &line[6]; *p != '\n'; i++, p++)
			start[i] = *p;
		start[i] = '\0';
		ppid = atoi(start);
		break;
	}
	fclose(fd);
	return ppid;
}

std::string get_process_cmdline(pid_t pid)
{
	std::string cmdl;
	char *name = (char *)alloca(MAX_PATH);
	if (name)
	{
		sprintf(name, "/proc/%d/cmdline", pid);
		FILE *f = fopen(name, "r");
		if (f)
		{
			size_t size;
			size = fread(name, sizeof(char), 1024, f);
			if (size > 0)
			{
				if ('\n' == name[size - 1])
					name[size - 1] = '\0';
			}
			fclose(f);
		}
	}

	cmdl = name;
	return sanitize_string(cmdl);
}

int process_read(int pid, void *dst, const void *src, size_t len)
{
	iovec local_iov, remote_iov;
	ssize_t nread;

	local_iov.iov_base = dst;
	local_iov.iov_len = len;

	remote_iov.iov_base = (void *)src;
	remote_iov.iov_len = len;

	nread = process_vm_readv(pid, &local_iov, 1, &remote_iov, 1, 0);
	if (nread == -1)
	{
		// Do not print error for inaccessible processes.
		if (errno != ESRCH)
		{
			printf("process_vm_readv failed. pid: %d: %s\n", pid, strerror(errno));
			return -1;
		}
	}
	else if (nread != len)
	{
		printf("process_vm_readv only read '%i' bytes out of the '%i' requested bytes. pid: %d\n", (int)nread, (int)len, pid);
	}

	return 0;
}

uint64_t get_proc_base(pid_t pid)
{
	char maps[MAX_PATH], line[4096];
	char *start, *p, *ret;
	int i;
	FILE *fd;
	Elf64_Addr base;

	snprintf(maps, MAX_PATH - 1, "/proc/%d/maps", pid);

	if ((fd = fopen(maps, "r")) == NULL)
	{
		printf("Cannot open %s for reading: %s\n", maps, strerror(errno));
		return -1;
	}

	while (fgets(line, sizeof(line), fd))
	{

		// Skip if earliest base address is module in /proc/<pid>/maps
		// Can be case for unpacked bins.
		ret = strstr(line, "/usr/lib");
		if (ret != nullptr)
			continue;

		// continue to find base addr of process.
		ret = strstr(line, "p ");
		ret = strstr(line, "/");
		if (ret == nullptr)
			continue;
		for (i = 0, start = (char *)alloca(32), p = line; *p != '-'; i++, p++)
			start[i] = *p;
		start[i] = '\0';
		base = strtoul(start, NULL, 16);
		break;
	}
	fclose(fd);
	return base;
}

std::string get_mod_name(pid_t pid, Elf64_Addr nameAddr)
{
	std::string module_name;
	// Get number of bytes upto next page boundary to assure bytes are readable.
	page_boundaries pBounds;
	get_page_boundaries(nameAddr, &pBounds);

	char *tmp_module_name = (char *)alloca(pBounds.page_sz);
	char *tmp_module_name_append = (char *)alloca(pBounds.page_sz);
	char *pch;

	if (process_read(pid, (void *)tmp_module_name, (void *)nameAddr, pBounds.bytes_to_next_page) == -1)
	{
		printf("Failed to read moduleName with process_read() in function 'get_mod_name': %s\n", strerror(errno));
		strcpy(tmp_module_name, "Failed to read Module Name");
	}

	// Does module path span more than one page of memory. If so read the next page and append the rest.
	// Remember MAX_PATH is 4096 bytes so the module name & path will not span more than 2 pages.
	int length = strlen(tmp_module_name);

	if ((length >= pBounds.bytes_to_next_page) && (tmp_module_name[pBounds.bytes_to_next_page - 1] != '\0'))
	{
		// We have an incomplete string, read the next page and append to output.
		if (process_read(pid, (void *)tmp_module_name_append, (void *)(nameAddr + pBounds.bytes_to_next_page), pBounds.page_sz) == -1)
		{
			printf("Failed to read moduleName with process_read() in function 'get_mod_name': %s\n", strerror(errno));
		}
		// Append to end of moduleName.
		strcpy(tmp_module_name + pBounds.bytes_to_next_page, tmp_module_name_append);
	}

	// Add check for ';' character as well as this signifies the end of the string table.
	// If we find ';' then replace it with an end of string '\0' character.
	pch = strstr(tmp_module_name, ";");
	if (pch != NULL)
		strncpy(pch, "\0", 1);

	module_name = tmp_module_name;

	return sanitize_string(module_name);
}



void get_fuzzy_hash_score(const char *mem, const char *disk, int *score)
{
	*score = fuzzy_compare(mem, disk);
}




/*
uint64_t get_text_base(pid_t pid)
{
	char maps[MAX_PATH], line[256];
	char *start, *p;
	FILE *fd;
	int i;
	Elf64_Addr base;

	snprintf(maps, MAX_PATH - 1, "/proc/%d/maps", pid);

	if ((fd = fopen(maps, "r")) == NULL)
	{
		printf("Cannot open %s for reading: %s\n", maps, strerror(errno));
		return -1;
	}

	while (fgets(line, sizeof(line), fd))
	{
		if (!strstr(line, "r-xp"))
			continue;
		for (i = 0, start = (char *)alloca(32), p = line; *p != '-'; i++, p++)
			start[i] = *p;
		start[i] = '\0';
		base = strtoul(start, NULL, 16);
		break;
	}
	fclose(fd);
	return base;
}
*/