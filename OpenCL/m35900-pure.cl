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

KERNEL_FQ void m35900_init (KERN_ATTR_TMPS (symfony_sha512_tmp_t))
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

  sha512_init (&ctx);
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

KERNEL_FQ void m35900_loop (KERN_ATTR_TMPS (symfony_sha512_tmp_t))
{
  /**
   * base
   */

  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT)
    return;

  u32 w[32];

  w[ 0] = tmps[gid].current_hash[ 0];
  w[ 1] = tmps[gid].current_hash[ 1];
  w[ 2] = tmps[gid].current_hash[ 2];
  w[ 3] = tmps[gid].current_hash[ 3];
  w[ 4] = tmps[gid].current_hash[ 4];
  w[ 5] = tmps[gid].current_hash[ 5];
  w[ 6] = tmps[gid].current_hash[ 6];
  w[ 7] = tmps[gid].current_hash[ 7];
  w[ 8] = tmps[gid].current_hash[ 8];
  w[ 9] = tmps[gid].current_hash[ 9];
  w[10] = tmps[gid].current_hash[10];
  w[11] = tmps[gid].current_hash[11];
  w[12] = tmps[gid].current_hash[12];
  w[13] = tmps[gid].current_hash[13];
  w[14] = tmps[gid].current_hash[14];
  w[15] = tmps[gid].current_hash[15];
  w[16] = 0;
  w[17] = 0;
  w[18] = 0;
  w[19] = 0;
  w[20] = 0;
  w[21] = 0;
  w[22] = 0;
  w[23] = 0;
  w[24] = 0;
  w[25] = 0;
  w[26] = 0;
  w[27] = 0;
  w[28] = 0;
  w[29] = 0;
  w[30] = 0;
  w[31] = 0;

  
  sha512_ctx_t ctx;

  for (u32 i = 0; i < LOOP_CNT; i++)
  {
    sha512_init (&ctx);

    sha512_update (&ctx, w, 64);
    sha512_update_swap (&ctx, pws[gid].i, pws[gid].pw_len);
    sha512_update_swap (&ctx, salt_bufs[SALT_POS_HOST].salt_buf_pc, salt_bufs[SALT_POS_HOST].salt_len_pc);
    sha512_final (&ctx);

    w[ 0] = h32_from_64_S (ctx.h[0]);
    w[ 1] = l32_from_64_S (ctx.h[0]);
    w[ 2] = h32_from_64_S (ctx.h[1]);
    w[ 3] = l32_from_64_S (ctx.h[1]);
    w[ 4] = h32_from_64_S (ctx.h[2]);
    w[ 5] = l32_from_64_S (ctx.h[2]);
    w[ 6] = h32_from_64_S (ctx.h[3]);
    w[ 7] = l32_from_64_S (ctx.h[3]);
    w[ 8] = h32_from_64_S (ctx.h[4]);
    w[ 9] = l32_from_64_S (ctx.h[4]);
    w[10] = h32_from_64_S (ctx.h[5]);
    w[11] = l32_from_64_S (ctx.h[5]);
    w[12] = h32_from_64_S (ctx.h[6]);
    w[13] = l32_from_64_S (ctx.h[6]);
    w[14] = h32_from_64_S (ctx.h[7]);
    w[15] = l32_from_64_S (ctx.h[7]);
  }

  tmps[gid].current_hash[ 0] = w[ 0];
  tmps[gid].current_hash[ 1] = w[ 1];
  tmps[gid].current_hash[ 2] = w[ 2];
  tmps[gid].current_hash[ 3] = w[ 3];
  tmps[gid].current_hash[ 4] = w[ 4];
  tmps[gid].current_hash[ 5] = w[ 5];
  tmps[gid].current_hash[ 6] = w[ 6];
  tmps[gid].current_hash[ 7] = w[ 7];
  tmps[gid].current_hash[ 8] = w[ 8];
  tmps[gid].current_hash[ 9] = w[ 9];
  tmps[gid].current_hash[10] = w[10];
  tmps[gid].current_hash[11] = w[11];
  tmps[gid].current_hash[12] = w[12];
  tmps[gid].current_hash[13] = w[13];
  tmps[gid].current_hash[14] = w[14];
  tmps[gid].current_hash[15] = w[15];

}

KERNEL_FQ void m35900_comp (KERN_ATTR_TMPS (symfony_sha512_tmp_t))
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
