# DSSSL Build Fix Prompt

## Context
DSSSL (Secure OpenSSL Fork) is failing to compile due to missing build configuration and compilation errors in the hybrid KEM implementation. The `tls13_hybrid_kem.c` file exists but is not included in the build system, and contains syntax errors that prevent compilation.

## Repository Information
- **Repository:** https://github.com/SWORDIntel/DSSSL
- **Branch:** `cursor/finish-ml-kem-implementation-composer-1-d503`
- **Issue:** Build fails with undefined references to hybrid KEM functions and compilation errors

## Problem 1: Missing Build Configuration

The file `ssl/tls13_hybrid_kem.c` exists but is not included in the build system. It needs to be added to `ssl/build.info`.

**File:** `ssl/build.info`

**Current code (around line 10):**
```
        methods.c t1_lib.c  t1_enc.c tls13_enc.c \
```

**Required change:**
Add `tls13_hybrid_kem.c` to the SOURCE list:
```
        methods.c t1_lib.c  t1_enc.c tls13_enc.c tls13_hybrid_kem.c \
```

## Problem 2: Compilation Error - OSSL_PARAM_END Usage

**File:** `ssl/tls13_hybrid_kem.c`  
**Line:** ~119

**Current code:**
```c
    *p++ = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, "SHA256", 0);
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, ikm, ikm_len);
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO, info, strlen(info));
    *p++ = OSSL_PARAM_construct_size_t(OSSL_KDF_PARAM_SIZE, combined_secret_len);
    *p = OSSL_PARAM_END;
```

**Error:** `OSSL_PARAM_END` is a struct initializer macro `{ NULL, 0, NULL, 0, 0 }` and cannot be assigned directly. It needs to be cast.

**Required fix:**
```c
    *p++ = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, "SHA256", 0);
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, ikm, ikm_len);
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO, info, strlen(info));
    *p++ = OSSL_PARAM_construct_size_t(OSSL_KDF_PARAM_SIZE, combined_secret_len);
    *p = (OSSL_PARAM)OSSL_PARAM_END;
```

## Problem 3: Unused Variables and Undefined Function

**File:** `ssl/tls13_hybrid_kem.c`  
**Function:** `tls13_hybrid_kem_required()` (around line 135)

**Current code:**
```c
int tls13_hybrid_kem_required(SSL *s)
{
    OSSL_LIB_CTX *libctx;
    DSMIL_POLICY_CTX *policy_ctx;
    DSMIL_PROFILE profile;
    int required = 0;

    if (s == NULL)
        return 0;

    /* Get policy context from SSL */
    /* TODO: Store policy context in SSL structure */
    libctx = SSL_get0_libctx(s);
    if (libctx == NULL)
        return 0;
```

**Issues:**
1. `libctx`, `policy_ctx`, and `profile` are declared but never used
2. `SSL_get0_libctx()` function doesn't exist in this OpenSSL version, causing implicit declaration warning

**Required fix:**
Remove unused variables and the problematic function call:
```c
int tls13_hybrid_kem_required(SSL *s)
{
    int required = 0;

    if (s == NULL)
        return 0;

    /* Get policy context from SSL */
    /* TODO: Store policy context in SSL structure */
    /* For now, check environment variable */
```

## Complete Diff Summary

### File 1: `ssl/build.info`
```diff
--- a/ssl/build.info
+++ b/ssl/build.info
@@ -7,7 +7,7 @@ SOURCE[../libssl]=\
         statem/statem_srvr.c statem/statem_clnt.c  s3_lib.c  s3_enc.c \
         statem/statem_lib.c statem/extensions.c statem/extensions_srvr.c \
         statem/extensions_clnt.c statem/extensions_cust.c s3_msg.c \
-        methods.c t1_lib.c  t1_enc.c tls13_enc.c \
+        methods.c t1_lib.c  t1_enc.c tls13_enc.c tls13_hybrid_kem.c \
         d1_lib.c d1_msg.c \
```

### File 2: `ssl/tls13_hybrid_kem.c`
```diff
--- a/ssl/tls13_hybrid_kem.c
+++ b/ssl/tls13_hybrid_kem.c
@@ -116,7 +116,7 @@ int tls13_hybrid_kem_combine_secrets(TLS13_HYBRID_KEM_CTX *ctx,
     *p++ = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, "SHA256", 0);
     *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, ikm, ikm_len);
     *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO, info, strlen(info));
     *p++ = OSSL_PARAM_construct_size_t(OSSL_KDF_PARAM_SIZE, combined_secret_len);
-    *p = OSSL_PARAM_END;
+    *p = (OSSL_PARAM)OSSL_PARAM_END;
 
     if (EVP_KDF_derive(kdf_ctx, combined_secret, *combined_secret_len, params) <= 0)
         goto err;
@@ -134,9 +134,6 @@ err:
  */
 int tls13_hybrid_kem_required(SSL *s)
 {
-    OSSL_LIB_CTX *libctx;
-    DSMIL_POLICY_CTX *policy_ctx;
-    DSMIL_PROFILE profile;
     int required = 0;
 
     if (s == NULL)
         return 0;
 
     /* Get policy context from SSL */
     /* TODO: Store policy context in SSL structure */
-    libctx = SSL_get0_libctx(s);
-    if (libctx == NULL)
-        return 0;
+    /* For now, check environment variable */
```

## Verification Steps

After applying these fixes, the build should succeed. To verify:

1. **Check build configuration:**
   ```bash
   cd dsssl
   grep "tls13_hybrid_kem.c" ssl/build.info
   ```
   Should show: `tls13_hybrid_kem.c` in the SOURCE list

2. **Build DSSSL:**
   ```bash
   cd dsssl/build  # or create build directory
   ../Configure --prefix=/path/to/install shared
   make -j$(nproc)
   ```
   Should compile without errors related to `tls13_hybrid_kem`.

3. **Check for undefined references:**
   ```bash
   make 2>&1 | grep -i "undefined reference.*hybrid_kem"
   ```
   Should return no results.

## Expected Outcome

After these fixes:
- ✅ `tls13_hybrid_kem.c` will be compiled as part of libssl
- ✅ No compilation errors related to `OSSL_PARAM_END`
- ✅ No warnings about unused variables
- ✅ No undefined references to hybrid KEM functions
- ✅ DSSSL builds successfully with hybrid KEM support

## Commit Message Suggestion

```
fix: Add tls13_hybrid_kem.c to build and fix compilation errors

- Add tls13_hybrid_kem.c to ssl/build.info SOURCE list
- Fix OSSL_PARAM_END usage (proper struct initializer cast)
- Remove unused variables in tls13_hybrid_kem_required()
- Fix libctx handling to avoid undefined function warnings

This enables successful compilation of DSSSL with hybrid KEM support.
```

## Additional Notes

- The `OSSL_PARAM_END` macro expands to `{ NULL, 0, NULL, 0, 0 }` which is a struct initializer, not a value. It must be cast to `OSSL_PARAM` type when assigning.
- The `SSL_get0_libctx()` function may not exist in all OpenSSL versions. The current implementation removes this dependency.
- These changes are minimal and focused on fixing compilation errors without changing the functional logic.
