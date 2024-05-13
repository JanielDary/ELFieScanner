#include "utils.h"
#include "elf_info.h"
#include "entry_point_scanner.h"
#include "library_scanner.h"
#include "shellcode_scanner.h"

void print_help(char *name)
{
	printf(R"EOF(
░█▀▀░█░░░█▀▀░▀█▀░█▀▀░░░░░█▀▀░█▀▀░█▀█░█▀█░█▀█░█▀▀░█▀▄
░█▀▀░█░░░█▀▀░░█░░█▀▀░▄▄▄░▀▀█░█░░░█▀█░█░█░█░█░█▀▀░█▀▄
░▀▀▀░▀▀▀░▀░░░▀▀▀░▀▀▀░░░░░▀▀▀░▀▀▀░▀░▀░▀░▀░▀░▀░▀▀▀░▀░▀)EOF");

	printf("\n\nUsage: %s [options] \n\n", name);
	printf("Option :\n");
	printf("   -p          					Scan single pid only\n");
	printf("   -e          					Run entrypoint scanner\n");
	printf("   -l          					Run library scanner\n");
	printf("   -s          					Run shellcode scanner\n");
	printf("   -c </path/to/config.json>    Supply path to heuristic configuration file\n");
	printf("   -h          					Display this help\n\n");
	printf("Examples :\n");
	printf("./ELFie -e -l -s -c c:/test/my_config.json		Run all scanners across all processes\n");
	printf("./ELFie -s -p 1604 -c c:/test/my_config.json 	Run shellcode scanner on process ID 1604\n");
}

void run_scanners_64(int scanner_selection, elf_info_64_group *elf_info_64_pots, config my_config)
{

	if (ENTRY_POINT_SCANNER == (scanner_selection & ENTRY_POINT_SCANNER))
	{
		entry_point_scanner_main_64(elf_info_64_pots, my_config);
	}

	if (LIBRARY_SCANNER == (scanner_selection & LIBRARY_SCANNER))
	{
		library_scanner_main_64(elf_info_64_pots, my_config);
	}

	if (SHELLCODE_SCANNER == (scanner_selection & SHELLCODE_SCANNER))
	{
		shellcode_scanner_main_64(elf_info_64_pots, my_config);
	}
}

void run_scanners_32(int scanner_selection, elf_info_32_group *elf_info_32_pots, config my_config)
{

	if (ENTRY_POINT_SCANNER == (scanner_selection & ENTRY_POINT_SCANNER))
	{
		entry_point_scanner_main_32(elf_info_32_pots, my_config);
	}

	if (LIBRARY_SCANNER == (scanner_selection & LIBRARY_SCANNER))
	{
		library_scanner_main_32(elf_info_32_pots, my_config);
	}

	if (SHELLCODE_SCANNER == (scanner_selection & SHELLCODE_SCANNER))
	{
		shellcode_scanner_main_32(elf_info_32_pots, my_config);
	}
}

int main(int argc, char **argv)
{
	std::vector<pid_t> pids, pids_32, pids_64, filtered_pids;
	std::vector<elf_info_64> elf_info_64_vector;
	std::vector<elf_info_32> elf_info_32_vector;
	pid_group pid_pots_64, pid_pots_32;
	elf_info_64_group elf_info_64_pots;
	elf_info_32_group elf_info_32_pots;
	int scanner_selection = 0;

	int textThreshold, single_pid, opt, rc;
	bool single_pid_mode = false;
	char *outputFile;

	pthread_t main_thread;
	pthread_t threads[THREAD_COUNT];
	// elf_info_thread_data_64 td[THREAD_COUNT];
	pthread_attr_t attr;
	void *status;
	sched_param param;
	utsname systeminfo;

	// Stores configuration info from json file.
	char *my_config_path;
	config my_config;

	if (argc < 2)
	{
		print_help(argv[0]);
		exit(EXIT_FAILURE);
	}

	// If character is followed by a colon is requires an argument.
	while ((opt = getopt(argc, argv, "elshp:c:")) != -1)
	{
		switch (opt)
		{
		case 'h':
			print_help(argv[0]);
			exit(EXIT_FAILURE);
			break;
		case 'p':
			single_pid = atoi(optarg);
			single_pid_mode = true;
			break;
		case 'e':
			scanner_selection |= ENTRY_POINT_SCANNER;
			break;
		case 'l':
			scanner_selection |= LIBRARY_SCANNER;
			break;
		case 's':
			scanner_selection |= SHELLCODE_SCANNER;
			break;
		case 'c':
			my_config_path = optarg;
			break;
		default: /* '?' */
			print_help(argv[0]);
			exit(EXIT_FAILURE);
		}
	}

	if (optind > argc)
	{
		print_help(argv[0]);
		exit(EXIT_FAILURE);
	}

	// Print System Info - For debugging purposes.
	uname(&systeminfo);
	printf("Sysname: %s\n", systeminfo.sysname);
	printf("Release: %s\n", systeminfo.release);
	printf("Version: %s\n", systeminfo.version);
	printf("Hostname: %s\n", systeminfo.nodename);

	if (!read_config(my_config_path, &my_config))
	{
		printf("Failed to read config file, exiting\n");
		exit(EXIT_FAILURE);
	}

	main_thread = pthread_self();

	set_cpu_affinity(&main_thread);

	// Set main thread priority value. Must be set to '0' if using SCHED_IDLE thread policy.
	param.sched_priority = 0;

	rc = pthread_setschedparam(main_thread, THREAD_POLICY, &param);
	if (rc != 0)
		exit(EXIT_FAILURE);

	// display_thread_sched_attr((char *)"Scheduler settings of main thread");

	pid_t pid;
	bool is_64_bit = false;
	bool is_32_bit = false;

	// Single PID mode.
	if (single_pid_mode)
	{
		if (!check_arch(single_pid, &is_64_bit, &is_32_bit))
		{
			printf("Invalid pid: %i", single_pid);
			return 1;
		}

		if (is_64_bit)
		{
			// Set pid to single pot
			pid_pots_64.pid_pots[0].push_back(single_pid);
			// Collect elf_info
			elf_info_main_64(&elf_info_64_vector, pid_pots_64);

			if (!elf_info_64_vector.empty())
			{
				// Create single elf_info pot with one elf_info result.
				generate_elf_info_64_pots(&elf_info_64_vector, &elf_info_64_pots);
				// Run scanners.
				run_scanners_64(scanner_selection, &elf_info_64_pots, my_config);
			}
			pthread_exit(NULL);
			return 0;
		}
		else if (is_32_bit)
		{
			pid_pots_32.pid_pots[0].push_back(single_pid);
			elf_info_main_32(&elf_info_32_vector, pid_pots_32);
			if (!elf_info_64_vector.empty())
			{
				generate_elf_info_32_pots(&elf_info_32_vector, &elf_info_32_pots);
				run_scanners_32(scanner_selection, &elf_info_32_pots, my_config);
			}
			pthread_exit(NULL);
			return 0;
		}
	}

	get_pids(&pids);
	filtered_pids = filter_pids(&pids);

	// Shuffle PID order so we don't have a single THREAD assigned to all lower PIDs (which generally higher privilege system processes that process_vm_read may not be able to attach to). Thus creating an unequal balance of work amongst each thread.
	// This should increase speed of the scanner.
	auto rng = std::default_random_engine{};
	shuffle(begin(filtered_pids), end(filtered_pids), rng);

	// Split into x86 & x64 pid groups.
	split_pids_into_32_64(&pids_64, &pids_32, filtered_pids);

	// Split into groups of PIDs
	generate_pid_pots(pids_64, &pid_pots_64);
	generate_pid_pots(pids_32, &pid_pots_32);

	// If we have 64-bit processes
	if (!pids_64.empty())
	{
		printf("Starting ELF_INFO 64-bit collection\n");
		elf_info_main_64(&elf_info_64_vector, pid_pots_64);
		printf("Finished ELF_INFO 64-bit collection\n");

		if (!elf_info_64_vector.empty())
		{
			// Generate x64 pid pots for scanners.
			generate_elf_info_64_pots(&elf_info_64_vector, &elf_info_64_pots);

			printf("Starting 64-bit scanners\n");
			run_scanners_64(scanner_selection, &elf_info_64_pots, my_config);
			printf("Finished 64-bit scanners\n");
		}
	}
	else
	{
		printf("No 64-bit processes found!\n");
	}

	// If we have 32-bit processes.
	if (!pids_32.empty())
	{
		printf("Starting ELF_INFO 32-bit collection\n");
		elf_info_main_32(&elf_info_32_vector, pid_pots_32);
		printf("Finished ELF_INFO 32-bit collection\n");

		if (!elf_info_32_vector.empty())
		{
			// Generate x86 pid pots for scanners.
			generate_elf_info_32_pots(&elf_info_32_vector, &elf_info_32_pots);

			printf("Starting 32-bit scanners\n");
			run_scanners_32(scanner_selection, &elf_info_32_pots, my_config);
			printf("Finished 32-bit scanners\n");
		}
	}
	else
	{
		printf("No 32-bit processes found!\n");
	}

	pthread_exit(NULL);
}