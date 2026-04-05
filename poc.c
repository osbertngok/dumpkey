// clang poc.c -o dumpkey -O3 -flto
//
// Extracts the SQLCipher encryption key from a running WeChat process on macOS.
//
// Strategy:
//   1. Read the first page of the encrypted .db file (contains salt + HMAC).
//   2. Scan the WeChat process's heap memory for the "rtree_i32" marker string.
//      This string comes from SQLite's R-Tree extension registration. In WeChat's
//      memory layout, the SQLCipher key happens to be stored 24 bytes after one
//      of the occurrences of this marker in the nano-malloc heap region.
//   3. There may be multiple "rtree_i32" occurrences in memory. For each one,
//      treat the 32 bytes at offset +24 as a candidate key and validate it by
//      recomputing the HMAC of the first database page. If the HMAC matches,
//      we found the correct key.
//
// Background — what is HMAC?
//   HMAC (Hash-based Message Authentication Code) is a mechanism to verify both
//   the integrity and authenticity of data. It combines a secret key with a hash
//   function (here SHA-1) to produce a fixed-size tag. Only someone who knows
//   the key can produce or verify the tag. Unlike a plain hash (which anyone can
//   recompute), an HMAC proves the data hasn't been tampered with AND that it
//   was produced by someone holding the correct key.
//
//   SQLCipher uses HMAC to protect each database page: after encrypting a page,
//   it computes HMAC-SHA1(hmac_key, page_content || page_number) and stores the
//   result in the page's reserved area. On read, it recomputes the HMAC and
//   compares — if they differ, the page was corrupted or the wrong key was used.
//   We exploit this: given a candidate key, we derive the HMAC key, recompute
//   the HMAC for page 1, and check if it matches. A match means we found the
//   correct encryption key.

#include <CommonCrypto/CommonCrypto.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <stdio.h>

// SQLCipher database constants (default settings used by WeChat)
#define DB_PAGE_SIZE 1024
#define SQLCIPHER_KEY_SIZE 32
#define SALT_SIZE 16
#define HMAC_SHA1_SIZE 20
#define IV_SIZE 16
#define AES_BLOCK_SIZE 16

// In WeChat's heap, the SQLCipher key is located 24 bytes after the
// "rtree_i32" marker string within the same allocation.
#define KEY_OFFSET_FROM_MARKER 24

// The "rtree_i32" string that SQLite registers for its R-Tree extension.
// Used as an anchor to locate the nearby encryption key in heap memory.
static const unsigned char RTREE_MARKER[] = {
    0x72, 0x74, 0x72, 0x65, 0x65, 0x5F, 0x69, 0x33, 0x32 // "rtree_i32"
};
#define RTREE_MARKER_SIZE sizeof(RTREE_MARKER)

// Validates a candidate SQLCipher key against the first page of the database.
//
// SQLCipher stores an HMAC-SHA1 in each page's reserved area. This function
// derives the HMAC key from the candidate key + salt (from the page header),
// computes the HMAC over the page body, and checks if it matches the stored HMAC.
//
// Returns true if the candidate key is correct.
bool validate_sqlcipher_key(const unsigned char *db_first_page,
                            const unsigned char *candidate_key) {
  if (!db_first_page || !candidate_key)
    return false;

  // Derive the HMAC salt by XOR-ing the database salt with 0x3A
  // (SQLCipher convention: hmac_salt = encryption_salt XOR 0x3A)
  unsigned char hmac_salt[SALT_SIZE];
  for (int i = 0; i < SALT_SIZE; i++)
    hmac_salt[i] = db_first_page[i] ^ 0x3A;

  // Derive the HMAC key using PBKDF2-HMAC-SHA1 with 2 iterations
  // (SQLCipher uses fast_kdf_iter=2 for the HMAC key derivation)
  unsigned char hmac_key[SQLCIPHER_KEY_SIZE];
  CCKeyDerivationPBKDF(kCCPBKDF2, (const char *)candidate_key,
                       SQLCIPHER_KEY_SIZE, hmac_salt, SALT_SIZE,
                       kCCPRFHmacAlgSHA1, 2, hmac_key, SQLCIPHER_KEY_SIZE);

  // Calculate where the HMAC is stored in the page.
  // The reserved area at the end of each page holds: IV + HMAC, rounded up
  // to an AES block boundary. The HMAC starts right after the IV.
  int reserved_size =
      ((IV_SIZE + HMAC_SHA1_SIZE + AES_BLOCK_SIZE - 1) / AES_BLOCK_SIZE) *
      AES_BLOCK_SIZE;
  int hmac_offset = DB_PAGE_SIZE - reserved_size + IV_SIZE;

  // Compute HMAC-SHA1 over the page content (after the salt, up to the HMAC)
  CCHmacContext hmac_ctx;
  CCHmacInit(&hmac_ctx, kCCHmacAlgSHA1, hmac_key, SQLCIPHER_KEY_SIZE);
  CCHmacUpdate(&hmac_ctx, db_first_page + SALT_SIZE, hmac_offset - SALT_SIZE);

  // SQLCipher includes the 1-based page number in the HMAC (little-endian)
  unsigned char page_number_le[4] = {1, 0, 0, 0};
  CCHmacUpdate(&hmac_ctx, page_number_le, 4);

  unsigned char computed_hmac[HMAC_SHA1_SIZE];
  CCHmacFinal(&hmac_ctx, computed_hmac);

  // If the computed HMAC matches the stored one, the candidate key is correct
  return memcmp(computed_hmac, db_first_page + hmac_offset, HMAC_SHA1_SIZE) ==
         0;
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

  // Read the first page of the encrypted database for HMAC validation
  unsigned char db_first_page[DB_PAGE_SIZE];
  FILE *fp = fopen(db_path, "rb");
  if (!fp || fread(db_first_page, 1, DB_PAGE_SIZE, fp) != DB_PAGE_SIZE) {
    fprintf(stderr, "failed to read db file\n");
    if (fp)
      fclose(fp);
    return -1;
  }
  fclose(fp);

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

    // Only scan RW regions tagged as nano-malloc heap.
    // WeChat's SQLCipher key resides in this type of allocation.
    if ((region_info.protection & VM_PROT_READ) &&
        (region_info.protection & VM_PROT_WRITE) &&
        (region_info.user_tag == VM_MEMORY_MALLOC_NANO)) {

      unsigned char *region_data = malloc(region_size);

      mach_vm_size_t bytes_read = 0;
      kr = mach_vm_read_overwrite(task_port, region_addr, region_size,
                                  (mach_vm_address_t)region_data, &bytes_read);
      if (kr != KERN_SUCCESS) {
        free(region_data);
        break;
      }

      // Scan this region for all occurrences of the "rtree_i32" marker
      unsigned char *scan_pos = region_data;
      unsigned char *region_end = region_data + bytes_read;
      while ((scan_pos = memmem(scan_pos, region_end - scan_pos, RTREE_MARKER,
                                RTREE_MARKER_SIZE))) {
        unsigned char *candidate_key = scan_pos + KEY_OFFSET_FROM_MARKER;
        if (candidate_key + SQLCIPHER_KEY_SIZE > region_end)
          break;

        // Validate this candidate key against the database's first page HMAC
        if (validate_sqlcipher_key(db_first_page, candidate_key)) {
          for (int i = 0; i < SQLCIPHER_KEY_SIZE; i++)
            sprintf(out_key_hex + i * 2, "%02x", candidate_key[i]);
          free(region_data);
          return 0;
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
