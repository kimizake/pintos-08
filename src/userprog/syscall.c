#include "userprog/syscall.h"
#include "userprog/process.h"
#include "userprog/pagedir.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/vaddr.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "devices/shutdown.h"

typedef int pid_t;
static struct lock filesys_lock;
#define SYSCALL_COUNT 13

typedef void(*syscall_ptr) (struct intr_frame *f, char* stack);

extern syscall_ptr syscall_functions[SYSCALL_COUNT] = {
        &syscall_halt_wrapper,
        &syscall_exit_wrapper,
        &syscall_exec_wrapper,
        &syscall_wait_wrapper,
        &syscall_create_wrapper,
        &syscall_remove_wrapper,
        &syscall_open_wrapper,
        &syscall_filesize_wrapper,
        &syscall_read_wrapper,
        &syscall_write_wrapper,
        &syscall_seek_wrapper,
        &syscall_tell_wrapper,
        &syscall_close_wrapper
};


static void syscall_handler (struct intr_frame *);

static bool is_valid_pointer (uint32_t*, uint32_t*);

static uint32_t * active_pd (void);


static void syscall_halt (void);
static pid_t syscall_exec (const char *, struct intr_frame *);
static int syscall_wait (pid_t);
static bool syscall_create (const char *, unsigned);
static bool syscall_remove (const char *);
static int syscall_open (const char *);
static int syscall_filesize (int);
static int syscall_read (int, void *, unsigned, struct intr_frame *);
static int syscall_write (int, const void *, unsigned);
static void syscall_seek (int, unsigned);
static unsigned syscall_tell (int);
static void syscall_close (int);

struct file_entry
  {
    int fd;
    struct file *file;
    struct list_elem fe_elem;
  };

struct file_entry*
get_file_entry (int fd)
{
  struct thread* thread_cur = thread_current ();

  struct file_entry *file_entry = NULL;
  struct list_elem *e;
  struct list *file_list = &thread_cur->file_list;

  for (e = list_begin (file_list); e != list_end (file_list);
       e = list_next (e))
  {
    struct file_entry *fe_cur = list_entry (e, struct file_entry, fe_elem);

    if (fe_cur->fd == fd) {
      file_entry = fe_cur;
      break;
    }
  }
  return file_entry;
}

static bool
is_valid_pointer (uint32_t* ptr, uint32_t *pd)
{
  return ptr != NULL && is_user_vaddr (ptr) && pagedir_get_page (pd, ptr) != NULL;
}

/* Returns the currently active page directory. */
static uint32_t *
active_pd (void)
{
  /* Copy CR3, the page directory base register (PDBR), into
     `pd'.
     See [IA32-v2a] "MOV--Move to/from Control Registers" and
     [IA32-v3a] 3.7.5 "Base Address of the Page Directory". */
  uintptr_t pd;
  asm volatile ("movl %%cr3, %0" : "=r" (pd));
  return ptov (pd);
}

void
syscall_init (void)
{
  lock_init (&filesys_lock);

  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

void free_files(void)
{
  struct thread* thread_cur = thread_current ();

  struct file_entry *file_entry = NULL;
  struct list_elem *e;
  struct list *file_list = &thread_cur->file_list;
  struct list_elem *next;

  lock_acquire(&filesys_lock);
  for (e = list_rbegin (file_list); e != list_rend (file_list);
       e = next)
  {
    struct file_entry *fe_cur = list_entry (e, struct file_entry, fe_elem);
    next = e->prev;
    free (fe_cur);
  }
  lock_release (&filesys_lock);
}

void
syscall_handler (struct intr_frame *f)
{
  if (!is_valid_pointer ((uint32_t*)f->esp, active_pd ())) {
    syscall_exit(ERROR, f);
  }
  uint32_t call_number = *(uint32_t*)f->esp;
  char* stack = (char*)f->esp;
  stack += 4;
  if (!is_valid_pointer ((void*)stack, active_pd ())) {
    syscall_exit (ERROR, f);
  }

  if (call_number < SYSCALL_COUNT) {
    (syscall_functions[call_number]) (f, stack);
  } else {
    printf ("system call! - Number: %d\n", call_number);
    thread_exit ();
  }
}

void
syscall_halt_wrapper (struct intr_frame *f UNUSED, char* stack UNUSED)
{
  syscall_halt ();
}

void
syscall_exit_wrapper (struct intr_frame *f, char* stack)
{
  syscall_exit ((int) *stack, f);
}

void
syscall_exec_wrapper (struct intr_frame *f, char* stack)
{
  if (!is_valid_pointer (*(char**)stack, active_pd ())) {
    syscall_exit(ERROR, f);
  }
  f->eax = syscall_exec (*(char**)stack, f);
}

void
syscall_wait_wrapper (struct intr_frame *f, char* stack)
{
  f->eax = syscall_wait (*stack);
}

void
syscall_create_wrapper (struct intr_frame *f, char* stack)
{
  if (!is_valid_pointer (*(char**)stack, active_pd ())) {
    syscall_exit (ERROR, f);
  }
  f->eax = syscall_create (*(char**)stack, *(int*)(stack + sizeof (char*)));
}

void
syscall_remove_wrapper (struct intr_frame *f, char* stack)
{
  if (!is_valid_pointer (*(char**)stack, active_pd ())) {
    syscall_exit (ERROR, f);
  }
  f->eax = syscall_remove (*(char**)stack);
}

void
syscall_open_wrapper (struct intr_frame *f, char* stack)
{
  if (!is_valid_pointer (*(char**)stack, active_pd ())) {
    syscall_exit (ERROR, f);
  }
  f->eax = syscall_open (*(char**)stack);
}

void
syscall_filesize_wrapper (struct intr_frame *f, char* stack)
{
  f->eax = syscall_filesize (*stack);
}

void
syscall_read_wrapper (struct intr_frame *f, char* stack)
{
  int fd = *(int*)stack;
  void* buffer= *(void**)(stack + sizeof (char*));
  unsigned size = *(unsigned*)(stack + 2*sizeof (char*));
  if (!is_valid_pointer (buffer, active_pd ())) {
    syscall_exit (ERROR, f);
  }
  f->eax = syscall_read (fd, buffer, size, f);
}

void
syscall_write_wrapper (struct intr_frame *f, char* stack)
{
  int fd = *(int*)stack;
  void* buffer= *(void**)(stack + sizeof (char*));
  unsigned size = *(unsigned*)(stack + 2*sizeof (char*));
  f->eax = syscall_write (fd, buffer, size);
  if (f->eax == ERROR)
    syscall_exit (ERROR, f);
}

void
syscall_seek_wrapper (struct intr_frame *f UNUSED, char* stack)
{
  syscall_seek (*(int*)stack, *(unsigned*)(stack + sizeof (char*)));
}

void
syscall_tell_wrapper (struct intr_frame *f, char* stack)
{
  f->eax = syscall_tell ((int)*stack);
}

void
syscall_close_wrapper (struct intr_frame *f UNUSED, char* stack)
{
  syscall_close (*stack);
}

static void
syscall_halt (void)
{
  shutdown_power_off ();
}

/* Terminates the user program and passes the exit status to the kernel. */
void
syscall_exit (int status, struct intr_frame *f)
{
  /* The return value is the EAX register */
  f->eax = status;
  thread_current ()->cp->has_exited = true;
  thread_current ()->cp->exit_code = status;
  printf ("%s: exit(%d)\n", thread_current ()->name, status);
  free_files ();

  lock_acquire (&filesys_lock);
  file_close (thread_current ()->executable);
  lock_release (&filesys_lock);
  struct child_process *cp = NULL;
  struct list_elem *e;
  struct list *child_processes = &thread_current ()->child_processes;
  struct list_elem *next;

  for (e = list_rbegin (child_processes); e != list_rend (child_processes);
       e = next)
  {
    struct child_process *cp = list_entry (e, struct child_process, child_elem);
    next = e->prev;
    if (cp->has_exited)
      free (cp);
  }

  process_exit ();
  thread_exit ();
}

static pid_t
syscall_exec (const char *cmd_line, struct intr_frame *f)
{

  pid_t pid = (pid_t) process_execute (cmd_line);
  struct child_process *cp;

  struct list_elem *e;
  for (e = list_rbegin (&thread_current ()->child_processes); e != list_rend (&thread_current ()->child_processes);
       e = list_prev (e))
  {
    cp = list_entry (e, struct child_process, child_elem);
    if (cp->tid == pid)
    {
      break;
    }
  }

  while (cp->loaded_status == LOAD_WAITING) {
    barrier ();
  }

  if (cp->loaded_status == LOAD_ERROR) {
    return ERROR;
  }
  return pid;
}

static int
syscall_wait (pid_t pid)
{
  return process_wait (pid);
}

static bool
syscall_create (const char *file, unsigned initial_size)
{
  bool result;
  lock_acquire (&filesys_lock);
  result = filesys_create (file, initial_size);
  lock_release (&filesys_lock);
  return result;
}

static bool
syscall_remove (const char *file)
{
  bool result;
  lock_acquire (&filesys_lock);
  result = filesys_remove (file);
  lock_release (&filesys_lock);
  return result;
}

static int
syscall_open (const char *file)
{
  if (file == NULL) {
    return ERROR;
  }
  int result;
  lock_acquire (&filesys_lock);

  struct file *f = filesys_open (file);
  if (f == NULL) {
    result = ERROR;
  } else {
    struct file_entry *fe = malloc (sizeof (struct file_entry));
    if (fe == NULL) {
      result = ERROR;
      file_close(f);
    }
    else {
      fe->fd = thread_current ()->fd_next++;
      fe->file = f;
      list_push_back(&thread_current ()->file_list, &fe->fe_elem);
      result = fe->fd;
    }
  }
  lock_release (&filesys_lock);
  return result;
}

static int
syscall_filesize (int fd)
{
  if (fd == STDOUT_FILENO)
    return ERROR;

  struct file_entry *fe = get_file_entry (fd);

  if (fe) {
    int result;
    lock_acquire (&filesys_lock);
    result = file_length (fe->file);
    lock_release (&filesys_lock);
    return result;
  }
  return ERROR;
}

static int
syscall_read (int fd, void *buffer, unsigned size, struct intr_frame *f)
{
  if (fd == STDOUT_FILENO)
    return ERROR;
  if (fd == STDIN_FILENO)
  {
    unsigned i = 0;
    char string[size];
    while (i < size) {
      /* Reads from keyboard using input_getc () */
      string[i] = (char) input_getc ();
      i++;
    }
    strlcpy (buffer, string, size);
    return i;
  }

  struct file_entry *fe = get_file_entry (fd);
  if (fe == NULL)
    syscall_exit (ERROR, f);
  int result;
  lock_acquire (&filesys_lock);
  result = file_read (fe->file, buffer, size);
  lock_release (&filesys_lock);
  return result;
}

static int
syscall_write (int fd, const void *buffer, unsigned size)
{
  if (size == 0)
    return 0;
  if (fd == STDIN_FILENO)
    return ERROR;
  if (!is_valid_pointer (buffer, active_pd ()))
    return ERROR;
  if (fd != STDOUT_FILENO) {
    struct file_entry *fe = get_file_entry (fd);
    if (fe == NULL)
      return ERROR;
    int result;
    lock_acquire (&filesys_lock);
    result = file_write (fe->file, buffer, size);
    lock_release (&filesys_lock);
    return result;
  }

  if (size < 100 && fd == STDOUT_FILENO) {
    putbuf ((char*)buffer, size);
    return size;
  }

  /* This is the normal case where we write the buffer contents to the file. */
}

static void
syscall_seek (int fd, unsigned position)
{
  struct file_entry *fe = get_file_entry (fd);

  if (fe) {
    lock_acquire (&filesys_lock);
    file_seek (fe->file, position);
    lock_release (&filesys_lock);
  }
}

static unsigned
syscall_tell (int fd)
{
  if (fd == STDOUT_FILENO || fd == STDIN_FILENO) {
    return ERROR;
  }
  struct file_entry *fe = get_file_entry (fd);
  if (fe == NULL)
    return ERROR;
  unsigned result;
  lock_acquire (&filesys_lock);
  result = file_tell (fe->file);
  lock_release (&filesys_lock);
  return result;
}

static void
syscall_close (int fd)
{
  if (fd == STDOUT_FILENO || fd == STDIN_FILENO) {
    return ERROR;
  }
  struct file_entry *fe = get_file_entry (fd);
  if (fe == NULL)
    return ERROR;

  if (fe) {
    lock_acquire (&filesys_lock);
    file_close (fe->file);
    lock_release (&filesys_lock);
  }
  list_remove (&fe->fe_elem);
  free (fe);
}
