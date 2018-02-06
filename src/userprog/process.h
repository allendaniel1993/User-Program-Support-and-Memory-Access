#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"

#define ARG_LEN 50
#define MAX_ARG 128
struct argument
{
char *arg; //points to starting address of argument 
size_t length; //lenth of the argument
void *esp; //address of the argument in stack
struct list_elem elem; //list for listing the argument
};
tid_t process_execute (const char *file_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);

struct file_details     
{
  int fd;		/*file descriptor of open file */
  struct file *file;	/* file pointer */
  struct list_elem elem;/* element to be added to the list */
};

struct file_details* get_file_details(int fd);
int get_file_size(int fd);
void close_file(int fd);
int open_file(char *fileName);
#endif /* userprog/process.h */
