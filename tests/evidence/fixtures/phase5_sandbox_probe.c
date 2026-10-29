/* Original Genewhip harmless Linux supervisor probe. MIT; no guest/ROM code. */
#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static atomic_int released;
static void delay_ms(long ms) {
    struct timespec ts = {ms / 1000, (ms % 1000) * 1000000L};
    while (nanosleep(&ts, &ts) != 0 && errno == EINTR) {}
}
static void *thread_wait(void *unused) {
    (void)unused;
    while (!atomic_load(&released)) delay_ms(1);
    return NULL;
}
static long cgroup(const char *name) {
    char path[128]; long value = -1;
    if (snprintf(path, sizeof(path), "/sys/fs/cgroup/%s", name) < 0) return -1;
    FILE *f = fopen(path, "r");
    if (f != NULL) { if (fscanf(f, "%ld", &value) != 1) value = -1; fclose(f); }
    return value;
}
static int pressure(int threads) {
    pthread_t tids[80]; pid_t pids[80]; int created = 0, error = 0;
    for (; created < 80; ++created) {
        if (threads) {
            error = pthread_create(&tids[created], NULL, thread_wait, NULL);
            if (error != 0) break;
        } else {
            pid_t pid = fork();
            if (pid < 0) { error = errno; break; }
            if (pid == 0) { for (;;) pause(); }
            pids[created] = pid;
        }
    }
    long current = cgroup("pids.current"), peak = cgroup("pids.peak");
    printf("PRESSURE mode=%s created=%d denied=%d current=%ld max=%ld peak=%ld\n",
           threads ? "threads" : "processes", created, error, current, cgroup("pids.max"), peak);
    fflush(stdout);
    atomic_store(&released, 1);
    for (int i = 0; i < created; ++i) {
        if (threads) pthread_join(tids[i], NULL);
        else { kill(pids[i], SIGKILL); while (waitpid(pids[i], NULL, 0) < 0 && errno == EINTR) {} }
    }
    return (error == EAGAIN && current == 64 && created > 0) ? 0 : 21;
}
static int job(const char *id) {
    int fd = open("/work/jobs.count", O_CREAT | O_RDWR, 0600);
    if (fd < 0 || flock(fd, LOCK_EX) != 0) return 31;
    int count = 0; (void)read(fd, &count, sizeof(count)); ++count;
    if (lseek(fd, 0, SEEK_SET) < 0 || write(fd, &count, sizeof(count)) != sizeof(count)) return 32;
    printf("JOB start %s active=%d\n", id, count); fflush(stdout);
    flock(fd, LOCK_UN); delay_ms(300);
    flock(fd, LOCK_EX); (void)lseek(fd, 0, SEEK_SET); (void)read(fd, &count, sizeof(count)); --count;
    (void)lseek(fd, 0, SEEK_SET); (void)write(fd, &count, sizeof(count));
    printf("JOB finish %s active=%d\n", id, count); fflush(stdout);
    flock(fd, LOCK_UN); close(fd); return count >= 0 && count <= 3 ? 0 : 33;
}
int main(int argc, char **argv) {
    if (argc < 2) return 2;
    if (strcmp(argv[1], "threads") == 0) return pressure(1);
    if (strcmp(argv[1], "processes") == 0) return pressure(0);
    if (strcmp(argv[1], "job") == 0 && argc == 3) return job(argv[2]);
    if (strcmp(argv[1], "sentinel") == 0) { puts("NATIVE_SENTINEL_OK"); return 0; }
    if (strcmp(argv[1], "memory") == 0 || strcmp(argv[1], "address-space") == 0) {
        int address_space = strcmp(argv[1], "address-space") == 0;
        size_t n = address_space ? (size_t)8 * 1024U * 1024U * 1024U : (size_t)512 * 1024U * 1024U;
        puts("BEFORE_ALLOC"); fflush(stdout);
        volatile unsigned char *p = malloc(n);
        if (p == NULL) { puts("ALLOC_DENIED"); return 0; }
        if (address_space) { puts("ALLOC_UNEXPECTEDLY_SUCCEEDED"); free((void *)p); return 41; }
        for (size_t i = 0; i < n; i += 4096) p[i] = 1;
        puts("ALLOC_UNEXPECTEDLY_SUCCEEDED"); free((void *)p); return 41;
    }
    if (strcmp(argv[1], "descendant") == 0 || strcmp(argv[1], "flood") == 0) {
        pid_t child = fork();
        if (child < 0) return 42;
        if (child == 0) { for (;;) pause(); }
        printf("DESCENDANT_STARTED %ld\n", (long)child); fflush(stdout);
        if (strcmp(argv[1], "flood") == 0) { for (;;) { puts("bounded authored output pressure"); } }
        for (;;) pause();
    }
    return 2;
}
