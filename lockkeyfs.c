/* lockkeyfs.c
 *
 * Simple prototype FUSE-backed encrypted filesystem using AES-256-GCM.
 * Per-file: MAGIC | SALT | IV | TAG | CIPHERTEXT
 *
 * Build (example):
 *   gcc -Wall -O2 lockkeyfs.c -o lockkeyfs `pkg-config --cflags --libs fuse openssl`
 *
 * Run:
 *   ./lockkeyfs <backing_dir> <mountpoint> -o nonempty
 */

#define FUSE_USE_VERSION 29

#include <fuse.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>
#include <dirent.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <limits.h>
#include <sys/types.h>
#include <termios.h>
#include <stdint.h>
#include <openssl/crypto.h>
#include <stdarg.h>
#include <sys/time.h>
#include <sys/stat.h>

#define MAGIC "LKFS"   /* 4 bytes */
#define SALT_LEN 16
#define IV_LEN 12      /* 12 bytes recommended for GCM */
#define TAG_LEN 16     /* 16 bytes auth tag */
#define KEY_LEN 32     /* AES-256 */
#define HEADER_LEN (4 + SALT_LEN + IV_LEN + TAG_LEN)

static char *backing_dir = NULL;
static const size_t MAX_FILE_BYTES = 32 * 1024 * 1024; /* 32 MB limit for prototype */

/* Global passphrase storage */
#define PASSPHRASE_MAX 128
static char g_passphrase[PASSPHRASE_MAX] = {0};

/* Helper: safe join */
static void join_path(const char *dir, const char *name, char *out, size_t outlen) {
    if (name[0] == '/')
        snprintf(out, outlen, "%s/%s", dir, name + 1);
    else
        snprintf(out, outlen, "%s/%s", dir, name);
}

/* Prompt for password with no echo */
static void get_password(char *pwd, size_t size) {
    struct termios oldt, newt;
    printf("Enter passphrase: ");
    fflush(stdout);
    if (tcgetattr(STDIN_FILENO, &oldt) != 0) {
        /* fallback to simple fgets if tcgetattr fails */
        if (fgets(pwd, size, stdin) == NULL) pwd[0] = 0;
        else pwd[strcspn(pwd, "\n")] = 0;
        printf("\n");
        return;
    }

    newt = oldt;
    newt.c_lflag &= ~ECHO;
    tcsetattr(STDIN_FILENO, TCSANOW, &newt);
    if (fgets(pwd, size, stdin) == NULL) {
        pwd[0] = 0;
    } else {
        pwd[strcspn(pwd, "\n")] = 0;  /* remove newline */
    }
    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
    printf("\n");
}

/* Derive key via PBKDF2 (used per-file with per-file salt) */
static int derive_key(const char *pass, const unsigned char *salt, unsigned char *key_out) {
    if (!PKCS5_PBKDF2_HMAC(pass, (int)strlen(pass),
                           salt, SALT_LEN,
                           100000, EVP_sha256(),
                           KEY_LEN, key_out)) {
        return -1;
    }
    return 0;
}

/* AES-256-GCM encrypt buffer. Produces ciphertext and auth tag. */
static int encrypt_buf_gcm(const unsigned char *plaintext, int plaintext_len,
                           const unsigned char *key, const unsigned char *iv,
                           unsigned char *tag_out,
                           unsigned char **ciphertext_out, int *cipher_len_out) {
    int ret = -1;
    EVP_CIPHER_CTX *ctx = NULL;
    unsigned char *cipher = NULL;
    int len = 0;
    int ciphertext_len = 0;

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) goto out;

    /* allocate ciphertext buffer: GCM is a stream-like AEAD, ciphertext length == plaintext_len */
    cipher = malloc((size_t)plaintext_len + EVP_CIPHER_block_size(EVP_aes_256_gcm()));
    if (!cipher) goto out;

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)) goto out;
    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, IV_LEN, NULL)) goto out;
    if (1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv)) goto out;

    /* No AAD used in this prototype */

    if (plaintext_len > 0) {
        if (1 != EVP_EncryptUpdate(ctx, cipher, &len, plaintext, plaintext_len)) goto out;
        ciphertext_len = len;
    } else {
        ciphertext_len = 0;
    }

    if (1 != EVP_EncryptFinal_ex(ctx, cipher + ciphertext_len, &len)) goto out;
    ciphertext_len += len;

    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_LEN, tag_out)) goto out;

    *ciphertext_out = cipher;
    *cipher_len_out = ciphertext_len;
    cipher = NULL; /* ownership transferred */
    ret = 0;

out:
    if (cipher) {
        OPENSSL_cleanse(cipher, plaintext_len + EVP_CIPHER_block_size(EVP_aes_256_gcm()));
        free(cipher);
    }
    if (ctx) EVP_CIPHER_CTX_free(ctx);
    return ret;
}

/* AES-256-GCM decrypt buffer. Verifies tag; returns -1 on auth failure. */
static int decrypt_buf_gcm(const unsigned char *ciphertext, int cipher_len,
                           const unsigned char *key, const unsigned char *iv,
                           const unsigned char *tag,
                           unsigned char **plaintext_out, int *plain_len_out) {
    int ret = -1;
    EVP_CIPHER_CTX *ctx = NULL;
    unsigned char *plain = NULL;
    int len = 0;
    int plaintext_len = 0;

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) goto out;

    /* allocate plaintext buffer */
    plain = malloc((size_t)cipher_len + EVP_CIPHER_block_size(EVP_aes_256_gcm()));
    if (!plain) goto out;

    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, IV_LEN, NULL)) goto out;
    if (1 != EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv)) goto out;

    /* No AAD used; must match encryption if used */

    if (cipher_len > 0) {
        if (1 != EVP_DecryptUpdate(ctx, plain, &len, ciphertext, cipher_len)) goto out;
        plaintext_len = len;
    } else {
        plaintext_len = 0;
    }

    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_LEN, (void *)tag)) goto out;

    /* EVP_DecryptFinal_ex returns >0 on success */
    if (EVP_DecryptFinal_ex(ctx, plain + plaintext_len, &len) <= 0) {
        goto out;
    }
    plaintext_len += len;

    *plaintext_out = plain;
    *plain_len_out = plaintext_len;
    plain = NULL; /* ownership transferred */
    ret = 0;

out:
    if (plain) {
        OPENSSL_cleanse(plain, cipher_len + EVP_CIPHER_block_size(EVP_aes_256_gcm()));
        free(plain);
    }
    if (ctx) EVP_CIPHER_CTX_free(ctx);
    return ret;
}

/* Read file from backing store, verify header, derive key using global passphrase and file salt, decrypt whole file */
static int read_decrypted_whole(const char *path, unsigned char **out, size_t *outlen) {
    char full[PATH_MAX];
    join_path(backing_dir, path, full, sizeof(full));

    FILE *f = fopen(full, "rb");
    if (!f) return -errno;

    unsigned char header[HEADER_LEN];
    if (fread(header, 1, HEADER_LEN, f) != HEADER_LEN) { fclose(f); return -EIO; }
    if (memcmp(header, MAGIC, 4) != 0) { fclose(f); return -EIO; }

    unsigned char salt[SALT_LEN];
    unsigned char iv[IV_LEN];
    unsigned char tag[TAG_LEN];
    memcpy(salt, header + 4, SALT_LEN);
    memcpy(iv, header + 4 + SALT_LEN, IV_LEN);
    memcpy(tag, header + 4 + SALT_LEN + IV_LEN, TAG_LEN);

    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return -EIO; }
    long fsize_total = ftell(f);
    if (fsize_total < 0) { fclose(f); return -EIO; }
    long cipher_len = fsize_total - HEADER_LEN;
    if (fseek(f, HEADER_LEN, SEEK_SET) != 0) { fclose(f); return -EIO; }
    if (cipher_len < 0 || (size_t)cipher_len > MAX_FILE_BYTES) { fclose(f); return -EFBIG; }

    unsigned char *cipher = NULL;
    if (cipher_len > 0) {
        cipher = malloc((size_t)cipher_len);
        if (!cipher) { fclose(f); return -ENOMEM; }
        if (fread(cipher, 1, (size_t)cipher_len, f) != (size_t)cipher_len) { free(cipher); fclose(f); return -EIO; }
    }
    fclose(f);

    if (g_passphrase[0] == 0) { if (cipher) { OPENSSL_cleanse(cipher, cipher_len); free(cipher); } return -EPERM; }
    unsigned char key[KEY_LEN];
    if (derive_key(g_passphrase, salt, key) != 0) { if (cipher) { OPENSSL_cleanse(cipher, cipher_len); free(cipher); } return -EIO; }

    unsigned char *plain = NULL;
    int plain_len = 0;
    int dec_ret = decrypt_buf_gcm(cipher, (int)cipher_len, key, iv, tag, &plain, &plain_len);
    if (cipher) { OPENSSL_cleanse(cipher, cipher_len); free(cipher); }
    OPENSSL_cleanse(key, sizeof(key));
    if (dec_ret != 0) {
        if (plain) { OPENSSL_cleanse(plain, plain_len); free(plain); }
        return -EIO;
    }

    *out = plain;
    *outlen = (size_t)plain_len;
    return 0;
}

/* Encrypt whole buffer and write to backing store with header (MAGIC|salt|iv|tag|ciphertext) */
static int write_encrypted_whole(const char *path, const unsigned char *data, size_t datalen) {
    char full[PATH_MAX];
    join_path(backing_dir, path, full, sizeof(full));

    unsigned char salt[SALT_LEN], iv[IV_LEN], tag[TAG_LEN];
    if (1 != RAND_bytes(salt, SALT_LEN)) return -EIO;
    if (1 != RAND_bytes(iv, IV_LEN)) return -EIO;

    if (g_passphrase[0] == 0) return -EPERM;
    unsigned char key[KEY_LEN];
    if (derive_key(g_passphrase, salt, key) != 0) return -EIO;

    unsigned char *cipher = NULL;
    int cipher_len = 0;
    if (encrypt_buf_gcm(data, (int)datalen, key, iv, tag, &cipher, &cipher_len) != 0) {
        OPENSSL_cleanse(key, sizeof(key));
        return -EIO;
    }

    OPENSSL_cleanse(key, sizeof(key));

    /* Safe temp filename allocation and mkstemp usage */
    size_t tmp_size = strlen(full) + strlen(".tmpXXXXXX") + 1;
    char *tmp = malloc(tmp_size);
    if (!tmp) { OPENSSL_cleanse(cipher, cipher_len); free(cipher); return -ENOMEM; }

    if (snprintf(tmp, tmp_size, "%s.tmpXXXXXX", full) >= (int)tmp_size) {
        OPENSSL_cleanse(cipher, cipher_len); free(cipher);
        free(tmp);
        return -ENAMETOOLONG;
    }

    int fd = mkstemp(tmp);
    if (fd < 0) { OPENSSL_cleanse(cipher, cipher_len); free(cipher); free(tmp); return -errno; }

    ssize_t w;
    /* write header then ciphertext */
    w = write(fd, MAGIC, 4);
    if (w != 4) { close(fd); unlink(tmp); OPENSSL_cleanse(cipher, cipher_len); free(cipher); free(tmp); return -EIO; }
    w = write(fd, salt, SALT_LEN);
    if (w != SALT_LEN) { close(fd); unlink(tmp); OPENSSL_cleanse(cipher, cipher_len); free(cipher); free(tmp); return -EIO; }
    w = write(fd, iv, IV_LEN);
    if (w != IV_LEN) { close(fd); unlink(tmp); OPENSSL_cleanse(cipher, cipher_len); free(cipher); free(tmp); return -EIO; }
    w = write(fd, tag, TAG_LEN);
    if (w != TAG_LEN) { close(fd); unlink(tmp); OPENSSL_cleanse(cipher, cipher_len); free(cipher); free(tmp); return -EIO; }

    if (cipher_len > 0) {
        w = write(fd, cipher, (size_t)cipher_len);
        if (w != cipher_len) { close(fd); unlink(tmp); OPENSSL_cleanse(cipher, cipher_len); free(cipher); free(tmp); return -EIO; }
    }

    /* ensure data is flushed to disk */
    fsync(fd);
    close(fd);

    /* wipe cipher from memory and free */
    OPENSSL_cleanse(cipher, cipher_len);
    free(cipher);

    if (rename(tmp, full) != 0) { unlink(tmp); free(tmp); return -errno; }
    free(tmp);
    return 0;
}

/* FUSE ops */

static int lk_getattr(const char *path, struct stat *stbuf) {
    memset(stbuf, 0, sizeof(struct stat));
    if (strcmp(path, "/") == 0) {
        stbuf->st_mode = S_IFDIR | 0755;
        stbuf->st_nlink = 2;
        return 0;
    }

    char _path[PATH_MAX];
    join_path(backing_dir, path, _path, sizeof(_path));

    struct stat st;
    if (stat(_path, &st) == 0) {
        unsigned char *plain = NULL;
        size_t plain_len = 0;
        int r = read_decrypted_whole(path, &plain, &plain_len);
        if (r == 0) {
            stbuf->st_mode = S_IFREG | 0644;
            stbuf->st_nlink = 1;
            stbuf->st_size = (off_t)plain_len;
            free(plain);
            return 0;
        } else if (r == -EPERM) {
            return -EPERM;
        }
        /* If we couldn't decrypt (bad passphrase etc.), fall back to on-disk size minus header */
        stbuf->st_mode = S_IFREG | 0644;
        stbuf->st_nlink = 1;
        stbuf->st_size = st.st_size > HEADER_LEN ? st.st_size - HEADER_LEN : 0;
        return 0;
    }
    return -ENOENT;
}

static int lk_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
               off_t offset, struct fuse_file_info *fi) {
    (void) offset; (void) fi;

    if (strcmp(path, "/") != 0) return -ENOENT;
    filler(buf, ".", NULL, 0);
    filler(buf, "..", NULL, 0);

    DIR *d = opendir(backing_dir);
    if (!d) return -errno;
    struct dirent *entry;
    while ((entry = readdir(d)) != NULL) {
        if (strcmp(entry->d_name, ".") && strcmp(entry->d_name, "..")) {
            filler(buf, entry->d_name, NULL, 0);
        }
    }
    closedir(d);
    return 0;
}

static int lk_open(const char *path, struct fuse_file_info *fi) {
    (void) fi;
    /* no special checks here; real implementations might check permissions
       or ensure file exists in backing store */
    char full[PATH_MAX];
    join_path(backing_dir, path, full, sizeof(full));
    if (access(full, F_OK) != 0) {
        return -ENOENT;
    }
    return 0;
}

static int lk_create(const char *path, mode_t mode, struct fuse_file_info *fi) {
    (void) mode; (void) fi;
    /* create empty encrypted file (zero-length plaintext) */
    return write_encrypted_whole(path, (const unsigned char *)"", 0);
}

static int lk_read(const char *path, char *buf, size_t size, off_t offset,
             struct fuse_file_info *fi) {
    (void) fi;
    unsigned char *plain = NULL;
    size_t plain_len = 0;
    int r = read_decrypted_whole(path, &plain, &plain_len);
    if (r < 0) return r;
    if ((size_t) offset < plain_len) {
        size_t tocopy = size;
        if ((size_t)offset + tocopy > plain_len) tocopy = plain_len - offset;
        memcpy(buf, plain + offset, tocopy);
        free(plain);
        return (int)tocopy;
    } else {
        free(plain);
        return 0;
    }
}

static int lk_write(const char *path, const char *buf, size_t size, off_t offset,
              struct fuse_file_info *fi) {
    (void) fi;
    unsigned char *plain = NULL;
    size_t plain_len = 0;
    int r = read_decrypted_whole(path, &plain, &plain_len);
    if (r == -EPERM) return -EPERM;
    if (r != 0) {
        /* file doesn't exist or couldn't be decrypted: create new plaintext buffer */
        plain_len = 0;
        plain = malloc((size_t)offset + size);
        if (!plain) return -ENOMEM;
        memset(plain, 0, (size_t)offset + size);
        plain_len = (size_t)offset + size;
    } else {
        /* ensure room for write */
        if ((size_t)offset + size > plain_len) {
            unsigned char *n = realloc(plain, (size_t)offset + size);
            if (!n) { free(plain); return -ENOMEM; }
            if ((size_t)offset > plain_len) memset(n + plain_len, 0, (size_t)offset - plain_len);
            plain = n;
            plain_len = (size_t)offset + size;
        }
    }

    memcpy(plain + offset, buf, size);

    /* write entire plaintext back (simple prototype) */
    int w =0;  
    /* cleanse plaintext from memory before freeing */
    OPENSSL_cleanse(plain, plain_len);
    free(plain);
    if (w != 0) return w;
    return (int)size;
}

static int lk_unlink(const char *path) {
    char full[PATH_MAX];
    join_path(backing_dir, path, full, sizeof(full));
    if (unlink(full) != 0) return -errno;
    return 0;
}

static const struct fuse_operations lk_oper = {
    .getattr = lk_getattr,
    .readdir = lk_readdir,
    .open    = lk_open,
    .create  = lk_create,
    .read    = lk_read,
    .write   = lk_write,
    .unlink  = lk_unlink,
};

int main(int argc, char *argv[]) {
       if (argc < 3) {
        fprintf(stderr, "Usage: %s <backing_dir> <mountpoint> [fuse-args]\n", argv[0]);
        return 1;
    }

    backing_dir = realpath(argv[1], NULL);
    if (!backing_dir) { perror("backing_dir"); return 1; }

    /* Build argv for fuse_main: drop argv[1] (backing_dir) */
    int newargc = argc - 1;
    char **newargv = malloc(sizeof(char*) * (newargc + 1));
    if (!newargv) { free(backing_dir); return 1; }

    newargv[0] = argv[0];
    /* copy pointers into newargv: skip backing_dir (argv[1]) */
    for (int i = 2; i < argc; ++i) {
        newargv[i-1] = argv[i];
    }
    newargv[newargc] = NULL;

    /* Prompt for passphrase once and store in g_passphrase */
   /* get_password(g_passphrase, sizeof(g_passphrase));*/

    for (int i=1;i<argc;++i){
	if(strncmp(argv[i],"--key=",6)==0){
		strncpy(g_passphrase,argv[i]+6,sizeof(g_passphrase)-1);
		argv[i]=NULL;
		break;
	     }
	}
       if (g_passphrase[0]==0){
	get_password(g_passphrase,sizeof(g_passphrase));
	}
    if (g_passphrase[0] == 0) {
        fprintf(stderr, "No passphrase provided. Exiting.\n");
        free(backing_dir);
        free(newargv);
        return 1;
    }

    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    int ret = fuse_main(newargc, newargv, &lk_oper, NULL);

    /* wipe passphrase from memory as best effort */
    OPENSSL_cleanse(g_passphrase, sizeof(g_passphrase));

    EVP_cleanup();
    ERR_free_strings();
    free(backing_dir);
    free(newargv);
    return ret;
}
