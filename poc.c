// clang poc.c -o dumpkey -O3 -flto

#include <CommonCrypto/CommonCrypto.h>
#include <ctype.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <stdio.h>
#include <string.h>

// WeChat 4.x uses WCDB (Tencent's SQLCipher fork) with 4096-byte pages.
// The encryption key is stored in memory as a WCDB keyspec string:
//   x'<64 lowercase hex chars (32-byte key)><32 lowercase hex chars (16-byte salt)>'
// Total: 99 bytes. See WCDB AbstractHandle.cpp: WCTAssert(rawCipherSize == 99)
#define DBPAGE_SIZE 4096
#define KEY_SIZE 32
#define SALT_SIZE 16
#define HMAC_SIZE 20
#define IV_SIZE 16
#define AES_BLOCK_SIZE 16

// WCDB keyspec format: x'<64 hex key chars><32 hex salt chars>'
// Lengths in hex chars (2 hex chars per byte)
#define KEY_HEX_LEN (KEY_SIZE * 2)   // 64
#define SALT_HEX_LEN (SALT_SIZE * 2) // 32
#define KEYSPEC_LEN (2 + KEY_HEX_LEN + SALT_HEX_LEN + 1) // 99: x'....'

bool testkey(const unsigned char *page, const unsigned char *key) {
  if (!page || !key)
    return false;

  unsigned char mac_salt[SALT_SIZE];
  for (int i = 0; i < SALT_SIZE; i++)
    mac_salt[i] = page[i] ^ 0x3A;

  unsigned char mac_key[KEY_SIZE];

  CCKeyDerivationPBKDF(kCCPBKDF2, (const char *)key, KEY_SIZE, mac_salt,
                       SALT_SIZE, kCCPRFHmacAlgSHA1, 2, mac_key, KEY_SIZE);

  int reserve = ((IV_SIZE + HMAC_SIZE + AES_BLOCK_SIZE - 1) / AES_BLOCK_SIZE) *
                AES_BLOCK_SIZE;
  int end = DBPAGE_SIZE - reserve + IV_SIZE;

  CCHmacContext hmacContext;
  CCHmacInit(&hmacContext, kCCHmacAlgSHA1, mac_key, KEY_SIZE);
  CCHmacUpdate(&hmacContext, page + SALT_SIZE, end - SALT_SIZE);

  unsigned char page_no[4] = {1, 0, 0, 0};
  CCHmacUpdate(&hmacContext, page_no, 4);

  unsigned char hmac_result[HMAC_SIZE];
  CCHmacFinal(&hmacContext, hmac_result);

  return memcmp(hmac_result, page + end, HMAC_SIZE) == 0;
}

// Parse a hex nibble. Returns -1 if not a valid hex char.
static int hexval(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

// Check if buf points to a valid WCDB keyspec: x'<96 hex chars>'
// If valid, decode the 32-byte key into out_key.
static bool parse_keyspec(const unsigned char *buf, unsigned char *out_key) {
  if (buf[0] != 'x' || buf[1] != '\'')
    return false;
  for (int i = 0; i < KEY_HEX_LEN + SALT_HEX_LEN; i++) {
    if (hexval(buf[2 + i]) < 0)
      return false;
  }
  if (buf[2 + KEY_HEX_LEN + SALT_HEX_LEN] != '\'')
    return false;

  // Decode the first 64 hex chars (32-byte key)
  for (int i = 0; i < KEY_SIZE; i++) {
    int hi = hexval(buf[2 + i * 2]);
    int lo = hexval(buf[2 + i * 2 + 1]);
    out_key[i] = (unsigned char)((hi << 4) | lo);
  }
  return true;
}

int dumpkey(pid_t pid, const char *filename, char *outkey) {
  mach_port_name_t target_task;
  kern_return_t kr;
  kr = task_for_pid(mach_task_self(), pid, &target_task);
  if (kr != KERN_SUCCESS) {
    fprintf(stderr, "%s (%d)\n", mach_error_string(kr), kr);
    return -1;
  }

  unsigned char page[DBPAGE_SIZE];
  FILE *fp = fopen(filename, "rb");
  if (!fp || fread(page, 1, DBPAGE_SIZE, fp) != DBPAGE_SIZE) {
    fprintf(stderr, "failed to read db file\n");
    if (fp)
      fclose(fp);
    return -1;
  }
  fclose(fp);

  // Prefix to search for: x' (start of WCDB keyspec)
  static const unsigned char KEYSPEC_PREFIX[] = {'x', '\''};

  mach_vm_address_t address = 0;
  mach_vm_size_t size;
  vm_region_extended_info_data_t info;
  mach_msg_type_number_t infoCnt = VM_REGION_EXTENDED_INFO_COUNT;
  mach_port_t object_name;

  while (1) {
    kr = mach_vm_region(target_task, &address, &size, VM_REGION_EXTENDED_INFO,
                        (vm_region_info_t)&info, &infoCnt, &object_name);
    if (kr != KERN_SUCCESS)
      break;

    if ((info.protection & VM_PROT_READ) && (info.protection & VM_PROT_WRITE)) {

      unsigned char *data = malloc(size);

      mach_vm_size_t outsize = 0;
      kr = mach_vm_read_overwrite(target_task, address, size,
                                  (mach_vm_address_t)data, &outsize);
      if (kr != KERN_SUCCESS) {
        free(data);
        address += size;
        continue;
      }

      unsigned char *pos = data, *end = pos + outsize;
      while ((pos = memmem(pos, end - pos, KEYSPEC_PREFIX,
                           sizeof(KEYSPEC_PREFIX)))) {
        if (pos + KEYSPEC_LEN <= end) {
          unsigned char candidate_key[KEY_SIZE];
          if (parse_keyspec(pos, candidate_key)) {
            if (testkey(page, candidate_key)) {
              for (int i = 0; i < KEY_SIZE; i++)
                sprintf(outkey + i * 2, "%02x", candidate_key[i]);
              free(data);
              return 0;
            }
          }
        }
        pos++;
      }
      free(data);
    }
    address += size;
  }

  return -1;
}

int main(int argc, char *argv[]) {
  if (argc < 3) {
    fprintf(stderr, "Usage: %s <pid> <dbfile>\n", argv[0]);
    return -1;
  }

  pid_t pid = atoi(argv[1]);

  char key[100] = {0};
  if (dumpkey(pid, argv[2], key) == 0) {
    printf("key: %s\n", key);
  } else {
    printf("not found key\n");
  }

  return 0;
}
