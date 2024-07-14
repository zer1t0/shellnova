#include "traceter.h"

#include <stdlib.h>
#include <sys/wait.h>
#include <stdint.h>
#include <asm/unistd_64.h>
#include <string.h>

#include <stdio.h>

#include "p_trace.h"
#include "utils.h"

#define nullanize(ptr) free(ptr); ptr = NULL
#define release(ptr) if(ptr){nullanize(ptr);}
#define release_file(fp) if(fp){fclose(fp); fp = NULL;}

#define SYSCALL_SIZE 2
#define SYSCALL_64 0x050f
#define SYSCALL_32 0x80cd

#define USER_MEM_MAX_ADDR_64 0x7fffffffffff
#define USER_MEM_MAX_ADDR_32 0xbfffffff

#ifdef __x86_64__
#define SYSCALL	SYSCALL_64
#define USER_MEM_MAX_ADDR USER_MEM_MAX_ADDR_64
#else
#define SYSCALL	SYSCALL_32
#define USER_MEM_MAX_ADDR USER_MEM_MAX_ADDR_32
#endif

__thread int errno_trace = 0;


static int _setregs(trace_session_t * session, struct user_regs_struct *regs){
    int ok = ptrace_setregs(session->pid, regs);
    if(-1 == ok){
        errno_trace = PTRACE_SETREGS_TRACE_ERROR;
    }
    return ok;
}

static int _getregs(trace_session_t * session, struct user_regs_struct *regs){
    int ok = ptrace_getregs(session->pid, regs);
    if(-1 == ok){
        errno_trace = PTRACE_GETREGS_TRACE_ERROR;
    }
    return ok;
}

unsigned long rax(trace_session_t * session) {
    struct user_regs_struct syscall_regs = {0};
    if(-1 == _getregs(session, &syscall_regs)){
        return -1;
    }

    return syscall_regs.rax;
}

unsigned long pt_get_rsp(trace_session_t *session) {
  struct user_regs_struct syscall_regs = {0};
  if (-1 == _getregs(session, &syscall_regs)) {
    return -1;
  }

  return syscall_regs.rsp;
}

unsigned long pt_get_rip(trace_session_t * session) {
    struct user_regs_struct syscall_regs = {0};
    if(-1 == _getregs(session, &syscall_regs)){
        return -1;
    }

    return syscall_regs.rip;
}

int pt_set_rip(trace_session_t* session, unsigned long rip) {
    struct user_regs_struct syscall_regs = {0};
    if (-1 == _getregs(session, &syscall_regs)) {
        return -1;
    }
    syscall_regs.rip = rip;

    return _setregs(session, &syscall_regs);
}

int pt_push(trace_session_t* session, unsigned long value) {
    struct user_regs_struct regs = {0};
    if (-1 == _getregs(session, &regs)) {
      return -1;
    }

    regs.rsp -= 8;

    if(ptrace_write_memory(session->pid, (void*)(regs.rsp), &value, 8) != 8) {
      return -1;
    }

    if(_setregs(session, &regs) != 0) {
      return -1;
    }

    return 0;
}


static int _continue(trace_session_t * session){
    int ok = ptrace_cont(session->pid, 0);
    if(-1 == ok){
        errno_trace = PTRACE_CONT_TRACE_ERROR;
    }
    return ok;
}


static bool was_stopped_by_sigtrap(int status){
    return WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP;
}


static int _wait_for_singlestep(trace_session_t * session) {
    int status = 0;
    if(waitpid(session->pid, &status, WUNTRACED) != session->pid) {
        return -1;
    }

    if(!was_stopped_by_sigtrap(status)){
        return -1;
    }
    return 0;
}


int pt_singlestep(trace_session_t * session){
    int ok = ptrace_singlestep(session->pid);
    if(-1 == ok){
        errno_trace = PTRACE_SINGLESTEP_TRACE_ERROR;
        return -1;
    }

    if(-1 == _wait_for_singlestep(session)) {
        return -1;
    }

    return ok;
}

size_t pt_copy_to_target(
    trace_session_t * session,
    void* remote_addr,
    void* data,
    size_t data_size
    ){
    size_t write_size = ptrace_write_memory(session->pid,
            remote_addr, data, data_size);
    if(data_size != write_size){
        errno_trace = PTRACE_WRITE_MEM_TRACE_ERROR;
        return -1;
    }
    return write_size;

}


static size_t _read_memory(trace_session_t * session,
        uint8_t *data, void* addr, size_t data_size){
    size_t read_size = ptrace_read_memory(session->pid,
            data, addr, data_size);
    if(data_size != read_size){
        errno_trace = PTRACE_READ_MEM_TRACE_ERROR;
        return -1;
    }
    return read_size;

}

int send_signal(trace_session_t * session, int signal){
    int ok = kill(session->pid, signal);
    if(ok == -1){
        errno_trace = SIGNAL_FAILED_TRACE_ERROR;
    }
    return ok;
}


int pt_attach_process(pid_t pid){
    if(current_process_arch() != process_arch(pid)){
        errno_trace = INCOMPATIBLE_ARCH_TRACE_ERROR;
        return -1;
    }

    if(ptrace_attach(pid) == -1){
        errno_trace = PTRACE_ATTACH_TRACE_ERROR;
        return -1;
    }

    int process_status = 0;
    if(waitpid(pid, &process_status, 0) != pid){
        errno_trace = WAIT_TRACE_ERROR;
        return -1;
    }

    if(!WIFSTOPPED(process_status)){
        errno_trace = NOT_STOPPED_TRACE_ERROR;
        return -1;
    }

    return 0;
}

static int detach_process(pid_t pid){
    return (int) ptrace_detach(pid);
}

static trace_session_t * new_trace_session(pid_t pid){
    trace_session_t *trace_session = calloc(sizeof(trace_session_t), 1);
    if(NULL == trace_session){
        return NULL;
    }
    trace_session->pid = pid;

    return trace_session;
}

static void release_trace_session(trace_session_t ** session){
    release(*session);
}


static bool _is_syscall_address(trace_session_t * session, void * addr){
    uint16_t ins = 0;
    int ok = _read_memory(session, (uint8_t*)&ins, addr, SYSCALL_SIZE);
    return -1 != ok && SYSCALL == ins;
}

int locate_syscall(trace_session_t* session) {
  void *syscall_addr = NULL;
  unsigned long pc = pt_get_rip(session);
  if (-1 == pc) {
    return -1;
  }

  if (_is_syscall_address(session, (void *)(pc - SYSCALL_SIZE))) {
      syscall_addr = (void *)(pc - SYSCALL_SIZE);
  } else if (_is_syscall_address(session, (void*)pc)) {
      syscall_addr = (void *)pc;
  }

  if(!syscall_addr) {
      return -1;
  }

  session->syscall = syscall_addr;

  return 0;
}

trace_session_t * init_trace_session(pid_t pid){
    if(-1 == pt_attach_process(pid)){
        return NULL;
    }

    trace_session_t *session = new_trace_session(pid);
    if(NULL == session){
        goto close_error;
    }

    locate_syscall(session);

    return session;

close_error:
    release_trace_session(&session);
    detach_process(pid);
    return NULL;
}

int resume_process(trace_session_t * session){
    if(-1 == _continue(session)){
        return -1;
    }
    return 0;
}

int stop_process(trace_session_t * session) {
    if(-1 == ptrace_interrupt(session->pid)){
        return -1;
    }
    return 0;
}

int terminate_session(trace_session_t ** session){
    detach_process((*session)->pid);
    release_trace_session(session);
    return 0;
}


static int _set_syscall_regs(trace_session_t * session,
        unsigned long syscall_number,
		unsigned long rdi, unsigned long rsi, unsigned long rdx,
		unsigned long r10, unsigned long r8, unsigned long r9){

    struct user_regs_struct syscall_regs = {0};

    if(-1 == _getregs(session, &syscall_regs)){
        return -1;
    }

    syscall_regs.rax = syscall_number;
    syscall_regs.rdi = rdi;
    syscall_regs.rsi = rsi;
    syscall_regs.rdx = rdx;
    syscall_regs.r10 = r10;
    syscall_regs.r8 = r8;
    syscall_regs.r9 = r9;

    if(NULL == session->syscall){
        errno_trace = NO_SYSCALL_ADDR_TRACE_ERROR;
        return -1;
    }
    syscall_regs.rip = (unsigned long) session->syscall;


    return _setregs(session, &syscall_regs);
}


static unsigned long _execute_syscall_core(trace_session_t * session,
        unsigned long syscall_number,
		unsigned long rdi, unsigned long rsi, unsigned long rdx,
		unsigned long r10, unsigned long r8, unsigned long r9) {

    if(-1 == _set_syscall_regs(session, syscall_number,
            rdi, rsi, rdx, r10, r8, r9)){
        return -1;
    }

    if(-1 == pt_singlestep(session)){
        return -1;
    }

    return rax(session);
}



static unsigned long _execute_syscall(trace_session_t * session,
        unsigned long syscall_number,
		unsigned long rdi, unsigned long rsi, unsigned long rdx,
		unsigned long r10, unsigned long r8, unsigned long r9) {

    struct user_regs_struct backup_regs = {0};


    if(-1 == _getregs(session, &backup_regs)) {
        return -1;
    }

    unsigned long result = _execute_syscall_core(session, syscall_number,
            rdi, rsi, rdx, r10, r8, r9);

    if(-1 == _setregs(session, &backup_regs)){
        return -1;
    }

    return result;
}

uid_t exec_getuid(trace_session_t * session){
    return (uid_t) _execute_syscall(session, __NR_getuid,
            0,0,0,0,0,0
    );
}

void * exec_mmap(trace_session_t * session,
        void *addr, size_t length, int prot, int flags, int fd, off_t offset) {
    unsigned long map_addr = _execute_syscall(session, __NR_mmap,
            (unsigned long) addr,
            (unsigned long) length,
            (unsigned long) prot,
            (unsigned long) flags,
            (unsigned long) fd,
            (unsigned long) offset
        );


    if(USER_MEM_MAX_ADDR < map_addr){
        map_addr = 0;
    }

    return (void*)map_addr;
}

int exec_munmap(trace_session_t * session, void *addr, size_t length) {
    return (int) _execute_syscall(session, __NR_munmap,
            (unsigned long) addr,
            (unsigned long) length,
            0,0,0,0
        );
}
