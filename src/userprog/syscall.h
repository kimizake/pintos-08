#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H
#define ERROR -1
#include "threads/interrupt.h"


void syscall_init (void);
void free_files (void);
void syscall_exit (int, struct intr_frame *);

void syscall_halt_wrapper (struct intr_frame *, char *);
void syscall_exit_wrapper (struct intr_frame *, char *);
void syscall_exec_wrapper (struct intr_frame *, char *);
void syscall_wait_wrapper (struct intr_frame *, char *);
void syscall_create_wrapper (struct intr_frame *, char *);
void syscall_remove_wrapper (struct intr_frame *, char *);
void syscall_open_wrapper (struct intr_frame *, char *);
void syscall_filesize_wrapper (struct intr_frame *, char *);
void syscall_read_wrapper (struct intr_frame *, char *);
void syscall_write_wrapper (struct intr_frame *, char *);
void syscall_seek_wrapper (struct intr_frame *, char *);
void syscall_tell_wrapper (struct intr_frame *, char *);
void syscall_close_wrapper (struct intr_frame *, char *);

#endif /* userprog/syscall.h */
