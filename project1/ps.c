#include <stdio.h>
#include <dirent.h>
#include <ctype.h>
#include <string.h>

#define MAX_SIZE 512

static int read_pid_state(const char *path, int *pid, char *state) {
    FILE *stat;
    int nread;
    if ((stat = fopen(path, "r")) == NULL) {
        // printf("%s: No such file\n", path);
        return -1;
    }
    nread = fscanf(stat, "%d %*s %c", pid, state);
    fclose(stat);    
    return nread;
}

static int read_cmdline(const char *path, char *buf) {
    FILE *cmdline;
    int nread = 0;
    if ((cmdline = fopen(path, "r")) == NULL) {
        printf("%s: No such file\n", path);
        return -1;
    }
    
    char c;
    while ((c = fgetc(cmdline)) != EOF && c != '\n') {
        buf[nread++] = c;
    }
    buf[nread] = '\0';
    
    fclose(cmdline);    
    return nread;    
}

int main(void)
{
    /* TODO */
    DIR *proc;
    struct dirent *entry;

    if ((proc = opendir("/proc")) == NULL) {
        perror("opendir");
        return -1;
    }

    /* Skip . and .. */
    readdir(proc);
    readdir(proc);

    printf("  PID S CMD\n");
    while ((entry = readdir(proc)) != NULL) {
        /* Skip files other than directory */
        if (entry->d_type != 4) continue;   // DT_DIR=4

        int pid; char state;
        char buf[MAX_SIZE];
        char path[MAX_SIZE];

        /* Read pid and state from /proc/pid/stat */
        sprintf(path, "/proc/%s/stat", entry->d_name);        
        if (read_pid_state(path, &pid, &state) < 0) {
            continue;
        }

        /* Read cmdline or comm */
        memset(path, 0, sizeof(path));
        sprintf(path, "/proc/%s/cmdline", entry->d_name);
        if (read_cmdline(path, buf) < 0) {
            continue;
        }
        if (strlen(buf) == 0) {
            memset(path, 0, sizeof(path));
            sprintf(path, "/proc/%s/comm", entry->d_name);
            read_cmdline(path, buf);
        }

        /* Output */
        printf("%5d %c %s\n", pid, state, buf);
    }

    closedir(proc);
    return 0;
}
