#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include <threads/vaddr.h>
#include <threads/synch.h>
#include <devices/shutdown.h>
#include <userprog/process.h>
#include <userprog/pagedir.h>
#include <filesys/filesys.h>
#include <filesys/file.h>

#define USER_VADDR_BOTTOM ((void *) 0x08048000)

static void syscall_handler (struct intr_frame *);
static void is_valid_user(void * esp);
void fetch_args(struct intr_frame *f, int *arg, int arg_count);
int execute(const char *name);
void exit(int status);
static void syscall_handler (struct intr_frame *);
int read_file(int fd, void *buffer, int size);
int write_file(int fd, void *buffer, int size);
int check_ptr(void *vaddr);

struct lock file_lock; /* lock for synchronisation */

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init(&file_lock);
}

/* check if buffer passed in read and write system calls are valid */
void check_buf(void* buffer, int size)
{
  
  if(buffer == NULL)exit(ERROR);
  char *buf = (char *) buffer;
  for (int i = 0; i < size; i++)
    {
      is_valid_user((void*)buf);
      buf++;
    }
}

/*check is the given ptr value is in the User memory and not in Kernel memory */
int check_ptr(void *vaddr)
{
  is_valid_user(vaddr);
  void *p1 = pagedir_get_page(thread_current()->pagedir,vaddr);
  if(!p1)
  exit(ERROR);
return (int) p1;
}

static void is_valid_user(void *vaddr){
if (!is_user_vaddr(vaddr)|| vaddr < USER_VADDR_BOTTOM){
   exit(ERROR);   
}
  void *p1 = pagedir_get_page(thread_current()->pagedir,vaddr);
  if(!p1)
  exit(ERROR);
}

/*fetch arguments from the stack and use it for system calls*/
void fetch_args(struct intr_frame *f, int *arg, int arg_count)
{
  int i;
  int *ptr;
  for (i = 0; i <arg_count; i++)
    {
      ptr = (int *) f->esp + i +1;
      is_valid_user((void *) ptr);
      check_ptr((const void *)ptr);
      arg[i] = *ptr;
    }
}

/* systemcall handler for various system calls */
static void
syscall_handler (struct intr_frame *f) 
{	
	is_valid_user((void *)f->esp);
	int syscall_num = * (int *)f->esp;
	int args[20];
	switch(syscall_num)
  	{
		case SYS_HALT:
		{
			shutdown_power_off();
			break;
		}
		case SYS_EXIT:
		{
			fetch_args(f,&args[0],1);
			int status = args[0];
			exit(status);
		}
		case SYS_WAIT:
		{
			fetch_args(f,&args[0],1);
			int pid = (int)args[0];
			f->eax = process_wait(pid);		
			break;
		}
		case SYS_EXEC:
		{
			fetch_args(f,&args[0],1);
			args[0] = check_ptr((const void *)args[0]);
			f->eax = execute(args[0]);		
			break;
		}
		case SYS_CREATE:
		{	
			fetch_args(f,&args[0],2);
			args[0] = check_ptr((const void *)args[0]);
			char *fileName = (const char *)args[0];
			if(fileName == NULL)
			{
				exit(ERROR);
			}
			int fileSize = (int )args[1];
			lock_acquire(&file_lock);
			f->eax = filesys_create(fileName,fileSize);	
			lock_release(&file_lock);
			break;
		}
		case SYS_REMOVE:
		{
			fetch_args(f,&args[0],1);
			char *fileName = (const char *)args[0];
			lock_acquire(&file_lock);
			f->eax = filesys_remove(fileName);
			lock_release(&file_lock);
			break;
		}
		case SYS_OPEN:
		{
			fetch_args(f,&args[0],1);
			args[0] = check_ptr((const void *)args[0]);
			char *fileName = (const char*)args[0];
			if(fileName == NULL)
			{
				exit(ERROR);
			}
		   	lock_acquire(&file_lock);
			f->eax = open_file(fileName);
			lock_release(&file_lock);
			break;
		}
		case SYS_FILESIZE:
		{
			fetch_args(f,&args[0],1);
			int fd = (int)args[0];
			lock_acquire(&file_lock);
			f->eax = get_file_size(fd);	
			lock_release(&file_lock);
			break;
		}
		case SYS_READ: 
		{
		
			fetch_args(f,&args[0],3);
			check_buf((void *)args[1],(int)args[2]);
			args[1] = check_ptr((const void *)args[1]);
			int fd = (int)args[0];		
			int size = (int)args[2];
			f->eax = read_file((int)args[0],(void *)args[1],size); 
			break;
		}

								     
		case SYS_WRITE: 
		{	
			fetch_args(f,&args[0],3);
			check_buf((void *)args[1],(int)args[2]);
			args[1] = check_ptr((const void *)args[1]);
			int fd = (int)args[0];		
			int size = (int)args[2];
			f->eax = write_file(fd,(void *)args[1],size); 
			break;
		}

		case SYS_SEEK:
		{
			fetch_args(f,&args[0],2);
			int fd = (int)args[0];
			struct file_details *file_detail = get_file_details(fd);
			int position = (int)args[1];
			lock_acquire(&file_lock);
			file_seek(file_detail->file,position);
			lock_acquire(&file_lock); 
			break;
		}
		case SYS_TELL:
		{
			fetch_args(f,&args[0],1);
			int fd = (int)args[0];
			struct file_details *file_detail = get_file_details(fd);
			lock_acquire(&file_lock);
			f->eax = file_tell(file_detail->file);
			lock_release(&file_lock); 
			break;
		}
		case SYS_CLOSE:
		{
			fetch_args(f,&args[0],1);
                        int fd  = (int)args[0];
			lock_acquire(&file_lock);
                        close_file(fd);
			lock_release(&file_lock);
			break;
		}
 	 }   
}

/* open a file given its filename */
int open_file(char *fileName)
{
  struct file *file_node = filesys_open(fileName);
  if(file_node == NULL)
  {
	return -1;
  }
  else
  {
  	struct file_details *f = malloc(sizeof(struct file_details));
  	if(f == NULL)return -1;
  	f->fd = thread_current()->fd_value;
  	thread_current()->fd_value++;    
  	f->file = file_node;
  	list_push_back(&thread_current()->file_table,&f->elem); 
  	return f->fd;
  }
}

/* close a file */
void close_file(int fd)
{
  struct list_elem *e;
  struct list *file_list = &thread_current()->file_table;
  int st = 0;
  for (e = list_begin (file_list); e != list_end (file_list);
       e = list_next (e))
    {
      struct file_details *file_det = list_entry (e, struct file_details, elem);
      if(file_det->fd == fd){
        file_close(file_det->file);
  	list_remove(e);
	st = 1;
	break;
      }
    }
    if(st == 0)exit(ERROR);
}

/* get file length */
int get_file_size(int fd)
{
  struct file_details *file_detail = get_file_details(fd);
  struct file *f = file_detail->file;
  int length = file_length(f);
  return length;
}

/* get file from given fd form the current threads open files */
struct file_details* get_file_details(int fd)
{
  struct list_elem *e;
  struct list *file_list = &thread_current()->file_table;

  for (e = list_begin (file_list); e != list_end (file_list);
       e = list_next (e))
    {
      struct file_details *file_det = list_entry (e, struct file_details, elem);
      if(file_det->fd == fd){
        return file_det;
      }
    }
    return NULL;
}

/* execute syscall */
int execute(const char *name){
	
 int pid = process_execute(name);
 return pid;
}

/*exit */
void exit(int status)
{
	printf ("%s: exit(%d)\n", thread_current()->name, status);
	thread_exit();
}

int read_file(int fd, void *buffer, int size)
{		
   	if(fd == 0)
	{
		int retVal = 0;
		uint8_t *read_buf=(uint8_t *) buffer;
		for(int i=0;i<size;i++)
		{	
			read_buf[i] = input_getc();
			retVal = i;
		}
		return retVal;
	}
	else
	{
		struct file_details *file_detail = get_file_details(fd);
		if(file_detail == NULL)
		{
		return -1;
		}
		lock_acquire(&file_lock);
		int count = file_read(file_detail->file, buffer, size);	
		lock_release(&file_lock);
		return count;
	}	
}

int write_file(int fd, void *buffer, int size)
{
	if(fd == 1)
	{
		putbuf(buffer,size);
		return size;
	}
	else
	{
			struct file_details *file_detail = get_file_details(fd);
			if(file_detail == NULL)
			{
				return -1;
			}
			else
			{
				lock_acquire(&file_lock);
				int bytes = file_write(file_detail->file, buffer, size);	
				lock_release(&file_lock);
				return bytes;
			}
	}
}
