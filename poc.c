// clang poc.c -o dumpkey -O3 -flto
//
// Extracts SQLCipher encryption keys for all WeChat 4.x databases in a folder.
//
// Usage:
//   sudo ./dumpkey <wechat_pid> <db_folder>
//
// Output: JSON mapping each db file (relative path) to its hex key.
//
// Strategy (WeChat 4.x / WCDB):
//   1. Recursively find all .db files under <db_folder> and read their salt
//      (first 16 bytes of the file, written by SQLCipher).
//   2. Scan the WeChat process's heap memory for WCDB keyspec strings.
//      WCDB stores each open database's key in memory as a 99-byte string:
//        x'<64 hex chars (32-byte key)><32 hex chars (16-byte salt)>'
//      See WCDB AbstractHandle.cpp: WCTAssert(rawCipherSize == 99)
//   3. For each keyspec found, decode the embedded salt and compare it against
//      every collected db file. A match identifies which key belongs to which db.
//      Each db has a unique randomly-generated salt, so there are no collisions.
//   4. Continue scanning until all db files are matched or memory is exhausted.
//   5. Output a JSON object: { "relative/path.db": "hexkey", ... }
//      Unmatched db files are omitted from the output.

#include <dirent.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

// SQLCipher/WCDB constants for WeChat 4.x
#define SQLCIPHER_KEY_SIZE 32
#define SALT_SIZE 16

// WCDB keyspec format: x'<64 hex key chars><32 hex salt chars>'
// Total: 2 + 64 + 32 + 1 = 99 bytes
// See: https://github.com/Tencent/wcdb — AbstractHandle.cpp: WCTAssert(rawCipherSize == 99)
#define KEY_HEX_LEN  (SQLCIPHER_KEY_SIZE * 2) // 64
#define SALT_HEX_LEN (SALT_SIZE * 2)          // 32
#define KEYSPEC_LEN  (2 + KEY_HEX_LEN + SALT_HEX_LEN + 1) // 99

#define MAX_DBS 256
#define MAX_PATH 1024

typedef struct {
  unsigned char salt[SALT_SIZE];
  char rel_path[MAX_PATH];                   // path relative to db_folder
  char key_hex[SQLCIPHER_KEY_SIZE * 2 + 1];  // hex key, set when found
  bool found;
} DbEntry;

// ── hex helpers ──────────────────────────────────────────────────────────────

static int hexval(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

// Check if buf is a valid WCDB keyspec; if so decode key and salt.
static bool parse_keyspec(const unsigned char *buf,
                          unsigned char *out_key, unsigned char *out_salt) {
  if (buf[0] != 'x' || buf[1] != '\'')
    return false;
  for (int i = 0; i < KEY_HEX_LEN + SALT_HEX_LEN; i++)
    if (hexval(buf[2 + i]) < 0)
      return false;
  if (buf[2 + KEY_HEX_LEN + SALT_HEX_LEN] != '\'')
    return false;

  for (int i = 0; i < SQLCIPHER_KEY_SIZE; i++) {
    int hi = hexval(buf[2 + i * 2]);
    int lo = hexval(buf[2 + i * 2 + 1]);
    out_key[i] = (unsigned char)((hi << 4) | lo);
  }
  for (int i = 0; i < SALT_SIZE; i++) {
    int hi = hexval(buf[2 + KEY_HEX_LEN + i * 2]);
    int lo = hexval(buf[2 + KEY_HEX_LEN + i * 2 + 1]);
    out_salt[i] = (unsigned char)((hi << 4) | lo);
  }
  return true;
}

// ── db file discovery ────────────────────────────────────────────────────────

// Recursively walk base/rel_prefix, appending found .db files into entries[].
static void collect_dbs(const char *base, const char *rel_prefix,
                        DbEntry *entries, int *n, int max) {
  char full[MAX_PATH];
  snprintf(full, sizeof(full), "%s%s%s",
           base, rel_prefix[0] ? "/" : "", rel_prefix);

  DIR *dir = opendir(full);
  if (!dir)
    return;

  struct dirent *ent;
  while ((ent = readdir(dir)) != NULL && *n < max) {
    if (ent->d_name[0] == '.')
      continue;

    char rel[MAX_PATH], abs_path[MAX_PATH];
    snprintf(rel, sizeof(rel), "%s%s%s",
             rel_prefix, rel_prefix[0] ? "/" : "", ent->d_name);
    snprintf(abs_path, sizeof(abs_path), "%s/%s", base, rel);

    struct stat st;
    if (stat(abs_path, &st) != 0)
      continue;

    if (S_ISDIR(st.st_mode)) {
      collect_dbs(base, rel, entries, n, max);
    } else if (S_ISREG(st.st_mode)) {
      size_t nlen = strlen(ent->d_name);
      if (nlen < 4 || strcmp(ent->d_name + nlen - 3, ".db") != 0)
        continue;

      FILE *fp = fopen(abs_path, "rb");
      if (!fp)
        continue;
      unsigned char salt[SALT_SIZE];
      bool ok = fread(salt, 1, SALT_SIZE, fp) == SALT_SIZE;
      fclose(fp);
      if (!ok)
        continue;

      DbEntry *e = &entries[*n];
      memcpy(e->salt, salt, SALT_SIZE);
      strncpy(e->rel_path, rel, MAX_PATH - 1);
      e->rel_path[MAX_PATH - 1] = '\0';
      e->key_hex[0] = '\0';
      e->found = false;
      (*n)++;
    }
  }
  closedir(dir);
}

// ── memory scanning ──────────────────────────────────────────────────────────

// Scan WeChat process memory for keyspecs and match against entries[].
// Returns number of keys found, or -1 on fatal error.
static int scan_process_memory(pid_t wechat_pid, DbEntry *entries, int n) {
  mach_port_name_t task_port;
  kern_return_t kr = task_for_pid(mach_task_self(), wechat_pid, &task_port);
  if (kr != KERN_SUCCESS) {
    fprintf(stderr, "task_for_pid: %s (%d)\n", mach_error_string(kr), kr);
    return -1;
  }

  static const unsigned char PREFIX[] = {'x', '\''};
  int found_count = 0;
  mach_vm_address_t region_addr = 0;
  mach_vm_size_t region_size;
  vm_region_extended_info_data_t region_info;
  mach_msg_type_number_t info_count = VM_REGION_EXTENDED_INFO_COUNT;
  mach_port_t object_name;

  while (found_count < n) {
    kr = mach_vm_region(task_port, &region_addr, &region_size,
                        VM_REGION_EXTENDED_INFO, (vm_region_info_t)&region_info,
                        &info_count, &object_name);
    if (kr != KERN_SUCCESS)
      break;

    if (!((region_info.protection & VM_PROT_READ) &&
          (region_info.protection & VM_PROT_WRITE))) {
      region_addr += region_size;
      continue;
    }

    unsigned char *region_data = malloc(region_size);
    if (!region_data) {
      region_addr += region_size;
      continue;
    }

    mach_vm_size_t bytes_read = 0;
    kr = mach_vm_read_overwrite(task_port, region_addr, region_size,
                                (mach_vm_address_t)region_data, &bytes_read);
    if (kr != KERN_SUCCESS) {
      free(region_data);
      region_addr += region_size;
      continue;
    }

    unsigned char *scan_pos = region_data;
    unsigned char *region_end = region_data + bytes_read;

    while ((scan_pos = memmem(scan_pos, region_end - scan_pos,
                              PREFIX, sizeof(PREFIX)))) {
      if (scan_pos + KEYSPEC_LEN <= region_end) {
        unsigned char candidate_key[SQLCIPHER_KEY_SIZE];
        unsigned char candidate_salt[SALT_SIZE];

        if (parse_keyspec(scan_pos, candidate_key, candidate_salt)) {
          for (int i = 0; i < n; i++) {
            if (!entries[i].found &&
                memcmp(candidate_salt, entries[i].salt, SALT_SIZE) == 0) {
              for (int j = 0; j < SQLCIPHER_KEY_SIZE; j++)
                sprintf(entries[i].key_hex + j * 2, "%02x", candidate_key[j]);
              entries[i].found = true;
              found_count++;
              break; // salt is unique per db — no need to check further entries
            }
          }
        }
      }
      scan_pos++;
    }

    free(region_data);
    region_addr += region_size;
  }

  return found_count;
}

// ── JSON output ───────────────────────────────────────────────────────────────

// Escape a string for JSON by escaping backslashes and double-quotes.
// WeChat db paths on macOS do not contain control characters, so this is
// sufficient without pulling in a JSON library.
static void print_json_string(const char *s) {
  putchar('"');
  for (; *s; s++) {
    if (*s == '"' || *s == '\\')
      putchar('\\');
    putchar(*s);
  }
  putchar('"');
}

static void print_json(const DbEntry *entries, int n) {
  printf("{\n");
  bool first = true;
  for (int i = 0; i < n; i++) {
    if (!entries[i].found)
      continue;
    if (!first)
      printf(",\n");
    printf("  ");
    print_json_string(entries[i].rel_path);
    printf(": ");
    print_json_string(entries[i].key_hex);
    first = false;
  }
  if (!first)
    printf("\n");
  printf("}\n");
}

// ── main ──────────────────────────────────────────────────────────────────────

int main(int argc, char *argv[]) {
  if (argc < 3) {
    fprintf(stderr, "Usage: %s <wechat_pid> <db_folder>\n", argv[0]);
    fprintf(stderr, "  Scans all .db files in <db_folder> recursively and\n"
                    "  outputs a JSON mapping of relative path -> hex key.\n");
    return 1;
  }

  pid_t wechat_pid = atoi(argv[1]);

  // Strip trailing slashes for clean relative paths
  char base[MAX_PATH];
  strncpy(base, argv[2], MAX_PATH - 1);
  base[MAX_PATH - 1] = '\0';
  size_t blen = strlen(base);
  while (blen > 1 && base[blen - 1] == '/')
    base[--blen] = '\0';

  DbEntry entries[MAX_DBS];
  int n = 0;
  collect_dbs(base, "", entries, &n, MAX_DBS);

  if (n == 0) {
    fprintf(stderr, "No .db files found in: %s\n", base);
    return 1;
  }

  fprintf(stderr, "Found %d .db file(s). Scanning WeChat process memory...\n", n);

  int found = scan_process_memory(wechat_pid, entries, n);
  if (found < 0)
    return 1;

  fprintf(stderr, "Matched %d/%d key(s).\n", found, n);

  print_json(entries, n);
  return 0;
}
