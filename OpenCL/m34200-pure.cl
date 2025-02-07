/**
 * Author......: kadalis
 * License.....: MIT
 */

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_vendor.h)
#include M2S(INCLUDE_PATH/inc_types.h)
#include M2S(INCLUDE_PATH/inc_platform.cl)
#include M2S(INCLUDE_PATH/inc_common.cl)
#include M2S(INCLUDE_PATH/inc_scalar.cl)
#include M2S(INCLUDE_PATH/inc_hash_sha512.cl)
#endif

#define COMPARE_S M2S(INCLUDE_PATH/inc_comp_single.cl)
#define COMPARE_M M2S(INCLUDE_PATH/inc_comp_multi.cl)

typedef struct symfony_sha512_tmp
{
  u32 current_hash[32];
} symfony_sha512_tmp_t;


void printf_hash (u32 *hash)
{
  u8 *to_print = (u8 *) hash;

  for (int i = 0; i < 16; i++)
    printf ("%1X ", to_print[i]);

  printf ("\n");
}

KERNEL_FQ void m34200_init (KERN_ATTR_TMPS (symfony_sha512_tmp_t))
{

  /**
   * base
   */

  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT)
    return;

  /**
   * init
   */

  sha512_ctx_t ctx;

  // printf("%s", (u8 *) salt_bufs[SALT_POS_HOST].salt_buf);
  sha512_init (&ctx);
  // print_hex(pws[gid].i, pws[gid].pw_len);
  sha512_update_global_swap (&ctx, pws[gid].i, pws[gid].pw_len);
  sha512_update_global_swap (&ctx, salt_bufs[SALT_POS_HOST].salt_buf_pc, salt_bufs[SALT_POS_HOST].salt_len_pc);
  sha512_final (&ctx);

  tmps[gid].current_hash[ 0] = h32_from_64_S (ctx.h[0]);
  tmps[gid].current_hash[ 1] = l32_from_64_S (ctx.h[0]);
  tmps[gid].current_hash[ 2] = h32_from_64_S (ctx.h[1]);
  tmps[gid].current_hash[ 3] = l32_from_64_S (ctx.h[1]);
  tmps[gid].current_hash[ 4] = h32_from_64_S (ctx.h[2]);
  tmps[gid].current_hash[ 5] = l32_from_64_S (ctx.h[2]);
  tmps[gid].current_hash[ 6] = h32_from_64_S (ctx.h[3]);
  tmps[gid].current_hash[ 7] = l32_from_64_S (ctx.h[3]);
  tmps[gid].current_hash[ 8] = h32_from_64_S (ctx.h[4]);
  tmps[gid].current_hash[ 9] = l32_from_64_S (ctx.h[4]);
  tmps[gid].current_hash[10] = h32_from_64_S (ctx.h[5]);
  tmps[gid].current_hash[11] = l32_from_64_S (ctx.h[5]);
  tmps[gid].current_hash[12] = h32_from_64_S (ctx.h[6]);
  tmps[gid].current_hash[13] = l32_from_64_S (ctx.h[6]);
  tmps[gid].current_hash[14] = h32_from_64_S (ctx.h[7]);
  tmps[gid].current_hash[15] = l32_from_64_S (ctx.h[7]);
  // printf_hash(tmps[gid].current_hash);
}

KERNEL_FQ void m34200_loop (KERN_ATTR_TMPS (symfony_sha512_tmp_t))
{
  /**
   * base
   */

  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT)
    return;

  sha512_ctx_t ctx;

  for (u32 i = 0; i < LOOP_CNT; i++)
  {
    sha512_init (&ctx);

    sha512_update_global (&ctx, tmps[gid].current_hash, 64);
    sha512_update_global_swap (&ctx, pws[gid].i, pws[gid].pw_len);
    sha512_update_global_swap (&ctx, salt_bufs[SALT_POS_HOST].salt_buf_pc, salt_bufs[SALT_POS_HOST].salt_len_pc);
    sha512_final (&ctx);

    tmps[gid].current_hash[ 0] = h32_from_64_S (ctx.h[0]);
    tmps[gid].current_hash[ 1] = l32_from_64_S (ctx.h[0]);
    tmps[gid].current_hash[ 2] = h32_from_64_S (ctx.h[1]);
    tmps[gid].current_hash[ 3] = l32_from_64_S (ctx.h[1]);
    tmps[gid].current_hash[ 4] = h32_from_64_S (ctx.h[2]);
    tmps[gid].current_hash[ 5] = l32_from_64_S (ctx.h[2]);
    tmps[gid].current_hash[ 6] = h32_from_64_S (ctx.h[3]);
    tmps[gid].current_hash[ 7] = l32_from_64_S (ctx.h[3]);
    tmps[gid].current_hash[ 8] = h32_from_64_S (ctx.h[4]);
    tmps[gid].current_hash[ 9] = l32_from_64_S (ctx.h[4]);
    tmps[gid].current_hash[10] = h32_from_64_S (ctx.h[5]);
    tmps[gid].current_hash[11] = l32_from_64_S (ctx.h[5]);
    tmps[gid].current_hash[12] = h32_from_64_S (ctx.h[6]);
    tmps[gid].current_hash[13] = l32_from_64_S (ctx.h[6]);
    tmps[gid].current_hash[14] = h32_from_64_S (ctx.h[7]);
    tmps[gid].current_hash[15] = l32_from_64_S (ctx.h[7]);
  }

}

KERNEL_FQ void m34200_comp (KERN_ATTR_TMPS (symfony_sha512_tmp_t))
{

  /**
   * modifier
   */

  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT)
    return;

  const u64 lid = get_local_id (0);

  const u32 r0 = hc_swap32_S (tmps[gid].current_hash[0]);
  const u32 r1 = hc_swap32_S (tmps[gid].current_hash[1]);
  const u32 r2 = hc_swap32_S (tmps[gid].current_hash[2]);
  const u32 r3 = hc_swap32_S (tmps[gid].current_hash[3]);

#define il_pos 0
#ifdef KERNEL_STATIC
#include COMPARE_M
#endif
}
