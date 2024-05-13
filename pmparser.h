#ifndef PMPARSER_H_
#define PMPARSER_H_

#include <elf.h>
#include <string>
#include <string.h>
#include <linux/limits.h>


#define PROCMAPS_LINE_MAX_LENGTH (PATH_MAX + 100) // Maximum line length in a procmaps file


typedef struct procmaps_struct
{
	void *addr_start;	  //< start address of the area
	void *addr_end;		  //< end address
	unsigned long length; //< size of the range

	char perm[5]; //< permissions rwxp
	short is_r;	  //< rewrote of perm with short flags
	short is_w;
	short is_x;
	short is_p;

	long offset;  //< offset
	char dev[12]; //< dev major:minor
	int inode;	  //< inode of the file that backs the area

	char pathname[600]; //< the path of the file that backs the area
	//chained list
	struct procmaps_struct *next; //<handler of the chinaed list
} procmaps_struct;


typedef struct procmaps_iterator
{
	procmaps_struct *head;
	procmaps_struct *current;
} procmaps_iterator;


// pmparser.cpp
procmaps_iterator *pmparser_parse(int pid);
procmaps_struct *pmparser_next(procmaps_iterator *p_procmaps_it);
void pmparser_free(procmaps_iterator *p_procmaps_it);
void _pmparser_split_line(char *buf, char *addr1, char *addr2, char *perm, char *offset, char *device, char *inode, char *pathname);
void pmparser_print(procmaps_struct *map, int order);


#endif