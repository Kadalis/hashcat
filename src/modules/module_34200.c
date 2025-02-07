/**
 * Author......: kadalis
 * License.....: MIT
 */

#include "common.h"
#include "types.h"
#include "modules.h"
#include "bitops.h"
#include "convert.h"
#include "shared.h"

static const u32 ATTACK_EXEC = ATTACK_EXEC_OUTSIDE_KERNEL;
static const u32 DGST_POS0 = 0;
static const u32 DGST_POS1 = 1;
static const u32 DGST_POS2 = 2;
static const u32 DGST_POS3 = 3;
static const u32 DGST_SIZE = DGST_SIZE_8_8;
static const u32 HASH_CATEGORY = HASH_CATEGORY_FRAMEWORK;
static const char *HASH_NAME = "Symfony SHA512";
static const u64 KERN_TYPE = 34200;

static const u32 OPTI_TYPE = OPTI_TYPE_ZERO_BYTE | OPTI_TYPE_USES_BITS_64;
static const u64 OPTS_TYPE = OPTS_TYPE_STOCK_MODULE | OPTS_TYPE_PT_GENERATE_LE | OPTS_TYPE_ST_BASE64 | OPTS_TYPE_MAXIMUM_THREADS;

static const u32 SALT_TYPE = SALT_TYPE_EMBEDDED;
static const char *ST_PASS = "hashcat";
static const char *ST_HASH = "$symfony_sha512$hd6vgkg8p20cwcgswwok8o8wcw8ogwwm$fTNRvO9hOXdxjVZ5KFuGxAZ9NQt1JniIxrKWhXlzp4DV0lYthltYTvdF6f+mmH37krMV3ri/cs8KiVYreHsYtw==";

u32 module_attack_exec (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  return ATTACK_EXEC;
}

u32 module_dgst_pos0 (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  return DGST_POS0;
}

u32 module_dgst_pos1 (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  return DGST_POS1;
}

u32 module_dgst_pos2 (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  return DGST_POS2;
}

u32 module_dgst_pos3 (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  return DGST_POS3;
}

u32 module_dgst_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  return DGST_SIZE;
}

u32 module_hash_category (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  return HASH_CATEGORY;
}

const char *module_hash_name (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  return HASH_NAME;
}

u64 module_kern_type (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  return KERN_TYPE;
}

u32 module_opti_type (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  return OPTI_TYPE;
}

u64 module_opts_type (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  return OPTS_TYPE;
}

u32 module_salt_type (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  return SALT_TYPE;
}

const char *module_st_hash (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  return ST_HASH;
}

const char *module_st_pass (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  return ST_PASS;
}


static const char *SIGNATURE_SYMFONY_SHA512 = "$symfony_sha512$";

typedef struct symfony_sha512_tmp
{
  u32 current_hash[32];         // 128 bytes. hash length 64 bytes
} symfony_sha512_tmp_t;


u64 module_tmp_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 tmp_size = (const u64) sizeof (symfony_sha512_tmp_t);

  return tmp_size;
}

int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, MAYBE_UNUSED const int line_len)
{
  u64 *digest = (u64 *) digest_buf;

  hc_token_t token;

  memset (&token, 0, sizeof (hc_token_t));

  token.token_cnt = 3;

  token.signatures_cnt = 1;
  token.signatures_buf[0] = SIGNATURE_SYMFONY_SHA512;

  token.len[0] = 16;
  token.attr[0] = TOKEN_ATTR_FIXED_LENGTH | TOKEN_ATTR_VERIFY_SIGNATURE;

  // salt
  token.sep[1] = '$';
  token.len_min[1] = 0;
  token.len_max[1] = 88;
  token.attr[1] = TOKEN_ATTR_VERIFY_LENGTH;

  // hash
  token.sep[2] = '$';
  token.len[2] = 88;
  token.attr[2] = TOKEN_ATTR_FIXED_LENGTH | TOKEN_ATTR_VERIFY_BASE64A;

  // check what is A/B/C for BASE64

  const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

  if (rc_tokenizer != PARSER_OK)
    return (rc_tokenizer);


  const u8 *salt_pos = token.buf[1];
  const int salt_len = token.len[1];
  
  memcpy ((u8 *) salt->salt_buf, salt_pos, salt_len);

  u8 *salt_pc_u8 = (u8 *) salt->salt_buf_pc;
  
  // concat braces to precomputed salt
  salt_pc_u8[0] = '{';
  memcpy (salt_pc_u8 + 1, salt_pos, salt_len);
  salt_pc_u8[salt_len + 1] = '}';
  
  salt->salt_len = salt_len;
  salt->salt_len_pc = salt_len + 2;


  u8 hash_buf[128];
  const int hash_decode_len = base64_decode (base64_to_int, token.buf[2], token.len[2], hash_buf);

  if (hash_decode_len > 64)
    return PARSER_HASH_LENGTH;

  memcpy ((u8 *) digest, hash_buf, 64);

  salt->salt_iter = 4999;

  return PARSER_OK;
}

void printf_hash (u32 *hash)
{
  u8 *to_print = (u8 *) hash;

  for (int i = 0; i < 16; i++)
    printf ("%1X ", to_print[i]);

  printf ("\n");
}

int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
{
  u64 *digest = (u64 *) digest_buf;

  // encoding hash
  u8 base64_hash_buf[128];
  memset (base64_hash_buf, 0, sizeof (base64_hash_buf));
  base64_encode (int_to_base64, (u8 *) digest, 64, base64_hash_buf);

  return snprintf (line_buf, line_size, "$symfony_sha512$%s$%s", (u8 *) salt->salt_buf, base64_hash_buf);
}

void module_init (module_ctx_t *module_ctx)
{
  module_ctx->module_context_size = MODULE_CONTEXT_SIZE_CURRENT;
  module_ctx->module_interface_version = MODULE_INTERFACE_VERSION_CURRENT;

  module_ctx->module_attack_exec = module_attack_exec;
  module_ctx->module_benchmark_esalt = MODULE_DEFAULT;
  module_ctx->module_benchmark_hook_salt = MODULE_DEFAULT;
  module_ctx->module_benchmark_mask = MODULE_DEFAULT;
  module_ctx->module_benchmark_charset = MODULE_DEFAULT;
  module_ctx->module_benchmark_salt = MODULE_DEFAULT;
  module_ctx->module_build_plain_postprocess = MODULE_DEFAULT;
  module_ctx->module_deep_comp_kernel = MODULE_DEFAULT;
  module_ctx->module_deprecated_notice = MODULE_DEFAULT;
  module_ctx->module_dgst_pos0 = module_dgst_pos0;
  module_ctx->module_dgst_pos1 = module_dgst_pos1;
  module_ctx->module_dgst_pos2 = module_dgst_pos2;
  module_ctx->module_dgst_pos3 = module_dgst_pos3;
  module_ctx->module_dgst_size = module_dgst_size;
  module_ctx->module_dictstat_disable = MODULE_DEFAULT;
  module_ctx->module_esalt_size = MODULE_DEFAULT;
  module_ctx->module_extra_buffer_size = MODULE_DEFAULT;
  module_ctx->module_extra_tmp_size = MODULE_DEFAULT;
  module_ctx->module_extra_tuningdb_block = MODULE_DEFAULT;
  module_ctx->module_forced_outfile_format = MODULE_DEFAULT;
  module_ctx->module_hash_binary_count = MODULE_DEFAULT;
  module_ctx->module_hash_binary_parse = MODULE_DEFAULT;
  module_ctx->module_hash_binary_save = MODULE_DEFAULT;
  module_ctx->module_hash_decode_postprocess = MODULE_DEFAULT;
  module_ctx->module_hash_decode_potfile = MODULE_DEFAULT;
  module_ctx->module_hash_decode_zero_hash = MODULE_DEFAULT;
  module_ctx->module_hash_decode = module_hash_decode;
  module_ctx->module_hash_encode_status = MODULE_DEFAULT;
  module_ctx->module_hash_encode_potfile = MODULE_DEFAULT;
  module_ctx->module_hash_encode = module_hash_encode;
  module_ctx->module_hash_init_selftest = MODULE_DEFAULT;
  module_ctx->module_hash_mode = MODULE_DEFAULT;
  module_ctx->module_hash_category = module_hash_category;
  module_ctx->module_hash_name = module_hash_name;
  module_ctx->module_hashes_count_min = MODULE_DEFAULT;
  module_ctx->module_hashes_count_max = MODULE_DEFAULT;
  module_ctx->module_hlfmt_disable = MODULE_DEFAULT;
  module_ctx->module_hook_extra_param_size = MODULE_DEFAULT;
  module_ctx->module_hook_extra_param_init = MODULE_DEFAULT;
  module_ctx->module_hook_extra_param_term = MODULE_DEFAULT;
  module_ctx->module_hook12 = MODULE_DEFAULT;
  module_ctx->module_hook23 = MODULE_DEFAULT;
  module_ctx->module_hook_salt_size = MODULE_DEFAULT;
  module_ctx->module_hook_size = MODULE_DEFAULT;
  module_ctx->module_jit_build_options = MODULE_DEFAULT;
  module_ctx->module_jit_cache_disable = MODULE_DEFAULT;
  module_ctx->module_kernel_accel_max = MODULE_DEFAULT;
  module_ctx->module_kernel_accel_min = MODULE_DEFAULT;
  module_ctx->module_kernel_loops_max = MODULE_DEFAULT;
  module_ctx->module_kernel_loops_min = MODULE_DEFAULT;
  module_ctx->module_kernel_threads_max = MODULE_DEFAULT;
  module_ctx->module_kernel_threads_min = MODULE_DEFAULT;
  module_ctx->module_kern_type = module_kern_type;
  module_ctx->module_kern_type_dynamic = MODULE_DEFAULT;
  module_ctx->module_opti_type = module_opti_type;
  module_ctx->module_opts_type = module_opts_type;
  module_ctx->module_outfile_check_disable = MODULE_DEFAULT;
  module_ctx->module_outfile_check_nocomp = MODULE_DEFAULT;
  module_ctx->module_potfile_custom_check = MODULE_DEFAULT;
  module_ctx->module_potfile_disable = MODULE_DEFAULT;
  module_ctx->module_potfile_keep_all_hashes = MODULE_DEFAULT;
  module_ctx->module_pwdump_column = MODULE_DEFAULT;
  module_ctx->module_pw_max = MODULE_DEFAULT;
  module_ctx->module_pw_min = MODULE_DEFAULT;
  module_ctx->module_salt_max = MODULE_DEFAULT;
  module_ctx->module_salt_min = MODULE_DEFAULT;
  module_ctx->module_salt_type = module_salt_type;
  module_ctx->module_separator = MODULE_DEFAULT;
  module_ctx->module_st_hash = module_st_hash;
  module_ctx->module_st_pass = module_st_pass;
  module_ctx->module_tmp_size = module_tmp_size;
  module_ctx->module_unstable_warning = MODULE_DEFAULT;
  module_ctx->module_warmup_disable = MODULE_DEFAULT;
}
