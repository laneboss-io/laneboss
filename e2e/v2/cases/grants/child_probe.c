//go:build ignore

// Standalone canary compiled by the Python proof, outside the Go package.
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc != 2) return 64;
    int rd = open(argv[1], O_RDONLY);
    int read_errno = rd < 0 ? errno : 0;
    if (rd >= 0) {
        close(rd);
        puts("{\"read_errno\":0}");
        return 41;
    }
    int wr = open(argv[1], O_WRONLY | O_APPEND);
    int write_errno = wr < 0 ? errno : 0;
    if (wr >= 0) {
        close(wr);
        printf("{\"read_errno\":%d,\"write_errno\":0}\n", read_errno);
        return 42;
    }
    printf("{\"read_errno\":%d,\"write_errno\":%d}\n",
           read_errno, write_errno);
    return 0;
}
