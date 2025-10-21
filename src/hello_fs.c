#define FUSE_USE_VERSION 31
#include <fuse.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>

#define FUSE_USE_VERSION 31
#include <fuse.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>

static int hello_getattr(const char *path, struct stat *stbuf,
                         struct fuse_file_info *fi) {
    memset(stbuf, 0, sizeof(struct stat));
    if (strcmp(path, "/") == 0) {
        stbuf->st_mode = S_IFDIR | 0755;
        stbuf->st_nlink = 2;
    } else if (strcmp(path, "/hello") == 0) {
        stbuf->st_mode = S_IFREG | 0444;
        stbuf->st_nlink = 1;
        stbuf->st_size = 18;
    } else
        return -ENOENT;
    return 0;
}

static int hello_readdir(const char *path, void *buf,
                         fuse_fill_dir_t filler, off_t offset,
                         struct fuse_file_info *fi) {
    (void) offset;
    (void) fi;

    if (strcmp(path, "/") != 0)
        return -ENOENT;

    filler(buf, ".", NULL, 0);
    filler(buf, "..", NULL, 0);
    filler(buf, "hello", NULL, 0);

    return 0;
}

static int hello_open(const char *path, struct fuse_file_info *fi) {
    if (strcmp(path, "/hello") != 0)
        return -ENOENT;
    return 0;
}

static int hello_read(const char *path, char *buf, size_t size,
                      off_t offset, struct fuse_file_info *fi) {
    const char *hello_str = "Hello Lock & Key!\n";
    size_t len = strlen(hello_str);
    if (strcmp(path, "/hello") != 0)
        return -ENOENT;

    if (offset < len){        
	 if (offset + size > len)
            size = len - offset;
        memcpy(buf, hello_str + offset, size);
    } else{
        size = 0;
	}
    return size;
}

static struct fuse_operations hello_ops = {
    .getattr = hello_getattr,
    .readdir = hello_readdir,
    .open = hello_open,
    .read = hello_read,
};

int main(int argc, char *argv[]) {
    return fuse_main(argc, argv, &hello_ops, NULL);
}
