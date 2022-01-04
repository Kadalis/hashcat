/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

//#define NEW_SIMD_CODE

#ifdef KERNEL_STATIC
#include "inc_vendor.h"
#include "inc_types.h"
#include "inc_platform.cl"
#include "inc_common.cl"
#include "inc_scalar.cl"
#include "inc_hash_ripemd160.cl"
#include "inc_cipher_aes.cl"
#endif

typedef struct cryptoapi
{
  u32 kern_type;
  u32 key_size;

} cryptoapi_t;

KERNEL_FQ void m14541_mxx (KERN_ATTR_ESALT (cryptoapi_t))
{
  /**
   * modifier
   */

  const u64 gid = get_global_id (0);

  /**
   * aes shared
   */

  #ifdef REAL_SHM

  const u64 lid = get_local_id (0);
  const u64 lsz = get_local_size (0);

  LOCAL_VK u32 s_te0[256];
  LOCAL_VK u32 s_te1[256];
  LOCAL_VK u32 s_te2[256];
  LOCAL_VK u32 s_te3[256];
  LOCAL_VK u32 s_te4[256];

  for (u32 i = lid; i < 256; i += lsz)
  {
    s_te0[i] = te0[i];
    s_te1[i] = te1[i];
    s_te2[i] = te2[i];
    s_te3[i] = te3[i];
    s_te4[i] = te4[i];
  }

  SYNC_THREADS ();

  #else

  CONSTANT_AS u32a *s_te0 = te0;
  CONSTANT_AS u32a *s_te1 = te1;
  CONSTANT_AS u32a *s_te2 = te2;
  CONSTANT_AS u32a *s_te3 = te3;
  CONSTANT_AS u32a *s_te4 = te4;

  #endif

  if (gid >= GID_MAX) return;

  /**
   * base
   */

  u32 aes_key_len = esalt_bufs[DIGESTS_OFFSET_HOST].key_size;

  ripemd160_ctx_t ctx0, ctx0_padding;

  ripemd160_init (&ctx0);

  u32 w[64] = { 0 };

  u32 w_len = 0;

  if (aes_key_len > 128)
  {
    w_len = pws[gid].pw_len;

    for (u32 i = 0; i < 64; i++) w[i] = pws[gid].i[i];

    ctx0_padding = ctx0;

    ctx0_padding.w0[0] = 0x00000041;

    ctx0_padding.len = 1;

    ripemd160_update (&ctx0_padding, w, w_len);
  }

  ripemd160_update_global (&ctx0, pws[gid].i, pws[gid].pw_len);

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos++)
  {
    ripemd160_ctx_t ctx = ctx0;

    if (aes_key_len > 128)
    {
      w_len = combs_buf[il_pos].pw_len;

      for (u32 i = 0; i < 64; i++) w[i] = combs_buf[il_pos].i[i];
    }

    ripemd160_update_global (&ctx, combs_buf[il_pos].i, combs_buf[il_pos].pw_len);

    ripemd160_final (&ctx);

    const u32 k0 = hc_swap32_S (ctx.h[0]);
    const u32 k1 = hc_swap32_S (ctx.h[1]);
    const u32 k2 = hc_swap32_S (ctx.h[2]);
    const u32 k3 = hc_swap32_S (ctx.h[3]);

    u32 k4 = 0, k5 = 0, k6 = 0, k7 = 0;

    if (aes_key_len > 128)
    {
      k4 = hc_swap32_S (ctx.h[4]);

      ripemd160_ctx_t ctx0_tmp = ctx0_padding;

      ripemd160_update (&ctx0_tmp, w, w_len);

      ripemd160_final (&ctx0_tmp);

      k5 = hc_swap32_S (ctx0_tmp.h[0]);

      if (aes_key_len > 192)
      {
        k6 = hc_swap32_S (ctx0_tmp.h[1]);
        k7 = hc_swap32_S (ctx0_tmp.h[2]);
      }
    }

    // key

    u32 ukey[8] = { 0 };

    ukey[0] = k0;
    ukey[1] = k1;
    ukey[2] = k2;
    ukey[3] = k3;

    if (aes_key_len > 128)
    {
      ukey[4] = k4;
      ukey[5] = k5;

      if (aes_key_len > 192)
      {
        ukey[6] = k6;
        ukey[7] = k7;
      }
    }

    // IV

    const u32 iv[4] = {
      hc_swap32_S(salt_bufs[SALT_POS_HOST].salt_buf[0]),
      hc_swap32_S(salt_bufs[SALT_POS_HOST].salt_buf[1]),
      hc_swap32_S(salt_bufs[SALT_POS_HOST].salt_buf[2]),
      hc_swap32_S(salt_bufs[SALT_POS_HOST].salt_buf[3])
    };

    // CT

    u32 CT[4] = { 0 };

    // aes

    u32 ks[60] = { 0 };

    if (aes_key_len == 128)
    {
      AES128_set_encrypt_key (ks, ukey, s_te0, s_te1, s_te2, s_te3);

      AES128_encrypt (ks, iv, CT, s_te0, s_te1, s_te2, s_te3, s_te4);
    }
    else if (aes_key_len == 192)
    {
      AES192_set_encrypt_key (ks, ukey, s_te0, s_te1, s_te2, s_te3);

      AES192_encrypt (ks, iv, CT, s_te0, s_te1, s_te2, s_te3, s_te4);
    }
    else
    {
      AES256_set_encrypt_key (ks, ukey, s_te0, s_te1, s_te2, s_te3);

      AES256_encrypt (ks, iv, CT, s_te0, s_te1, s_te2, s_te3, s_te4);
    }

    const u32 r0 = CT[0];
    const u32 r1 = CT[1];
    const u32 r2 = CT[2];
    const u32 r3 = CT[3];

    COMPARE_M_SCALAR (r0, r1, r2, r3);
  }
}

KERNEL_FQ void m14541_sxx (KERN_ATTR_ESALT (cryptoapi_t))
{
  /**
   * modifier
   */

  const u64 gid = get_global_id (0);

  /**
   * aes shared
   */

  #ifdef REAL_SHM

  const u64 lid = get_local_id (0);
  const u64 lsz = get_local_size (0);

  LOCAL_VK u32 s_te0[256];
  LOCAL_VK u32 s_te1[256];
  LOCAL_VK u32 s_te2[256];
  LOCAL_VK u32 s_te3[256];
  LOCAL_VK u32 s_te4[256];

  for (u32 i = lid; i < 256; i += lsz)
  {
    s_te0[i] = te0[i];
    s_te1[i] = te1[i];
    s_te2[i] = te2[i];
    s_te3[i] = te3[i];
    s_te4[i] = te4[i];
  }

  SYNC_THREADS ();

  #else

  CONSTANT_AS u32a *s_te0 = te0;
  CONSTANT_AS u32a *s_te1 = te1;
  CONSTANT_AS u32a *s_te2 = te2;
  CONSTANT_AS u32a *s_te3 = te3;
  CONSTANT_AS u32a *s_te4 = te4;

  #endif

  if (gid >= GID_MAX) return;

  /**
   * digest
   */

  const u32 search[4] =
  {
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R0],
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R1],
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R2],
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R3]
  };

  /**
   * base
   */

  u32 aes_key_len = esalt_bufs[DIGESTS_OFFSET_HOST].key_size;

  ripemd160_ctx_t ctx0, ctx0_padding;

  ripemd160_init (&ctx0);

  u32 w[64] = { 0 };

  u32 w_len = 0;

  if (aes_key_len > 128)
  {
    w_len = pws[gid].pw_len;

    for (u32 i = 0; i < 64; i++) w[i] = pws[gid].i[i];

    ctx0_padding = ctx0;

    ctx0_padding.w0[0] = 0x00000041;

    ctx0_padding.len = 1;

    ripemd160_update (&ctx0_padding, w, w_len);
  }

  ripemd160_update_global (&ctx0, pws[gid].i, pws[gid].pw_len);

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos++)
  {
    ripemd160_ctx_t ctx = ctx0;

    if (aes_key_len > 128)
    {
      w_len = combs_buf[il_pos].pw_len;

      for (u32 i = 0; i < 64; i++) w[i] = combs_buf[il_pos].i[i];
    }

    ripemd160_update_global (&ctx, combs_buf[il_pos].i, combs_buf[il_pos].pw_len);

    ripemd160_final (&ctx);

    const u32 k0 = hc_swap32_S (ctx.h[0]);
    const u32 k1 = hc_swap32_S (ctx.h[1]);
    const u32 k2 = hc_swap32_S (ctx.h[2]);
    const u32 k3 = hc_swap32_S (ctx.h[3]);

    u32 k4 = 0, k5 = 0, k6 = 0, k7 = 0;

    if (aes_key_len > 128)
    {
      k4 = hc_swap32_S (ctx.h[4]);

      ripemd160_ctx_t ctx0_tmp = ctx0_padding;

      ripemd160_update (&ctx0_tmp, w, w_len);

      ripemd160_final (&ctx0_tmp);

      k5 = hc_swap32_S (ctx0_tmp.h[0]);

      if (aes_key_len > 192)
      {
        k6 = hc_swap32_S (ctx0_tmp.h[1]);
        k7 = hc_swap32_S (ctx0_tmp.h[2]);
      }
    }

    // key

    u32 ukey[8] = { 0 };

    ukey[0] = k0;
    ukey[1] = k1;
    ukey[2] = k2;
    ukey[3] = k3;

    if (aes_key_len > 128)
    {
      ukey[4] = k4;
      ukey[5] = k5;

      if (aes_key_len > 192)
      {
        ukey[6] = k6;
        ukey[7] = k7;
      }
    }

    // IV

    const u32 iv[4] = {
      hc_swap32_S(salt_bufs[SALT_POS_HOST].salt_buf[0]),
      hc_swap32_S(salt_bufs[SALT_POS_HOST].salt_buf[1]),
      hc_swap32_S(salt_bufs[SALT_POS_HOST].salt_buf[2]),
      hc_swap32_S(salt_bufs[SALT_POS_HOST].salt_buf[3])
    };

    // CT

    u32 CT[4] = { 0 };

    // aes

    u32 ks[60] = { 0 };

    if (aes_key_len == 128)
    {
      AES128_set_encrypt_key (ks, ukey, s_te0, s_te1, s_te2, s_te3);

      AES128_encrypt (ks, iv, CT, s_te0, s_te1, s_te2, s_te3, s_te4);
    }
    else if (aes_key_len == 192)
    {
      AES192_set_encrypt_key (ks, ukey, s_te0, s_te1, s_te2, s_te3);

      AES192_encrypt (ks, iv, CT, s_te0, s_te1, s_te2, s_te3, s_te4);
    }
    else
    {
      AES256_set_encrypt_key (ks, ukey, s_te0, s_te1, s_te2, s_te3);

      AES256_encrypt (ks, iv, CT, s_te0, s_te1, s_te2, s_te3, s_te4);
    }

    const u32 r0 = CT[0];
    const u32 r1 = CT[1];
    const u32 r2 = CT[2];
    const u32 r3 = CT[3];

    COMPARE_S_SCALAR (r0, r1, r2, r3);
  }
}
