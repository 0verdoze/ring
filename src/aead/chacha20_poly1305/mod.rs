// Copyright 2015-2025 Brian Smith.
//
// Permission to use, copy, modify, and/or distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
//
// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
// SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
// OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
// CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

#[allow(unused_imports)]
use crate::polyfill::prelude::*;

use super::{
    chacha::{self, Counter, Overlapping},
    poly1305, Aad, AuthError, ForgedPlaintext, Nonce, Tag,
};
use crate::{
    cpu,
    error::InputTooLongError,
    polyfill::{sliceutil, u64_from_usize, usize_from_u64_saturated},
};
use cfg_if::cfg_if;

cfg_if! {
    if #[cfg(any(
            all(target_arch = "aarch64", target_endian = "little"),
            target_arch = "x86_64"))] {
        use cpu::GetFeature as _;
        mod integrated;
    }
}

pub(super) const KEY_LEN: usize = chacha::KEY_LEN;

const MAX_IN_OUT_LEN: usize = super::max_input_len(64, 1);
// https://tools.ietf.org/html/rfc8439#section-2.8
const _MAX_IN_OUT_LEN_BOUNDED_BY_RFC: () =
    assert!(MAX_IN_OUT_LEN == usize_from_u64_saturated(274_877_906_880u64));

#[derive(Clone)]
pub(super) struct Key(chacha::Key);

impl Key {
    pub(super) fn new(value: [u8; KEY_LEN]) -> Self {
        Self(chacha::Key::new(value))
    }

    #[inline(never)]
    pub(super) fn open_within<'o>(
        &self,
        nonce: Nonce,
        aad: Aad<&[u8]>,
        in_out: Overlapping<'o>,
        received_tag: &Tag,
        forged_plaintext: ForgedPlaintext,
        cpu_features: cpu::Features,
    ) -> Result<&'o mut [u8], AuthError> {
        super::open_within(in_out, received_tag, forged_plaintext, |in_out| {
            open(self, nonce, aad, in_out, cpu_features)
        })
    }

    #[inline(never)]
    pub(super) fn seal(
        &self,
        nonce: Nonce,
        aad: Aad<&[u8]>,
        in_out: &mut [u8],
        cpu: cpu::Features,
    ) -> Result<Tag, InputTooLongError> {
        #[cfg(any(
            all(target_arch = "aarch64", target_endian = "little"),
            target_arch = "x86_64"
        ))]
        if let Some(required) = cpu.get_feature() {
            return integrated::seal(self, nonce, aad, in_out, required, cpu.get_feature());
        }

        seal_fallback(self, nonce, aad, in_out, cpu)
    }
}

#[cfg(not(target_os = "espidf"))]
pub(super) fn seal_fallback(
    Key(chacha20_key): &Key,
    nonce: Nonce,
    aad: Aad<&[u8]>,
    in_out: &mut [u8],
    cpu: cpu::Features,
) -> Result<Tag, InputTooLongError> {
    let (counter, poly1305_key) = begin(chacha20_key, nonce, aad, in_out, cpu)?;
    let mut auth = poly1305::Context::from_key(poly1305_key, cpu);

    poly1305_update_padded_16(&mut auth, aad.as_ref());
    chacha20_key.encrypt(counter, in_out.into(), cpu);
    poly1305_update_padded_16(&mut auth, in_out);
    Ok(finish(auth, aad.as_ref().len(), in_out.len()))
}

#[cfg(target_os = "espidf")]
pub(super) fn seal_fallback(
    Key(chacha20_key): &Key,
    nonce: Nonce,
    aad: Aad<&[u8]>,
    in_out: &mut [u8],
    _cpu: cpu::Features,
) -> Result<Tag, InputTooLongError> {
    use super::TAG_LEN;

    let mut tag = [0u8; TAG_LEN];
    let raw_nonce = *nonce.as_ref();

    let ret = unsafe {
        esp_idf_sys::mbedtls_chachapoly_encrypt_and_tag(
            &chacha20_key.ctx.0 as *const _ as *mut _,
            in_out.len(),
            raw_nonce.as_ptr(),
            aad.0.as_ptr(),
            aad.0.len(),
            in_out.as_ptr(),
            in_out.as_mut_ptr(),
            tag.as_mut_ptr(),
        )
    };

    if ret != 0 {
        panic!("`mbedtls_chachapoly_encrypt_and_tag` failed");
    }

    Ok(tag.into())
}

fn open(
    key: &Key,
    nonce: Nonce,
    aad: Aad<&[u8]>,
    in_out: Overlapping<'_>,
    cpu: cpu::Features,
) -> Result<Tag, InputTooLongError> {
    #[cfg(any(
        all(target_arch = "aarch64", target_endian = "little"),
        target_arch = "x86_64"
    ))]
    if let Some(required) = cpu.get_feature() {
        return integrated::open(key, nonce, aad, in_out, required, cpu.get_feature());
    }

    open_fallback(key, nonce, aad, in_out, cpu)
}

#[cfg(not(target_os = "espidf"))]
pub(super) fn open_fallback(
    Key(chacha20_key): &Key,
    nonce: Nonce,
    aad: Aad<&[u8]>,
    in_out: Overlapping<'_>,
    cpu: cpu::Features,
) -> Result<Tag, InputTooLongError> {
    let (counter, poly1305_key) = begin(chacha20_key, nonce, aad, in_out.input(), cpu)?;
    let mut auth = poly1305::Context::from_key(poly1305_key, cpu);

    poly1305_update_padded_16(&mut auth, aad.as_ref());
    poly1305_update_padded_16(&mut auth, in_out.input());
    let in_out_len = in_out.len();
    chacha20_key.encrypt(counter, in_out, cpu);
    Ok(finish(auth, aad.as_ref().len(), in_out_len))
}

#[cfg(target_os = "espidf")]
pub(super) fn open_fallback(
    Key(chacha20_key): &Key,
    nonce: Nonce,
    aad: Aad<&[u8]>,
    in_out: Overlapping<'_>,
    cpu: cpu::Features,
) -> Result<Tag, InputTooLongError> {
    use super::TAG_LEN;
    use esp_idf_sys::mbedtls_chachapoly_context;

    let mut tag = [0u8; TAG_LEN];
    let raw_nonce = *nonce.as_ref();

    // since there is no access to chachapoly_crypt_and_tag (its not exported/marked as static)
    // we need to do same things as it does internally

    unsafe {
        let ctx = &chacha20_key.ctx.0 as *const mbedtls_chachapoly_context as *mut mbedtls_chachapoly_context;

        let ret = esp_idf_sys::mbedtls_chachapoly_starts(
            ctx,
            raw_nonce.as_ptr(),
            esp_idf_sys::mbedtls_chachapoly_mode_t_MBEDTLS_CHACHAPOLY_DECRYPT,
        );
        if ret != 0 { return Err(InputTooLongError::new(0)); }

        let ret = esp_idf_sys::mbedtls_chachapoly_update_aad(
            ctx,
            aad.0.as_ptr(),
            aad.0.len(),
        );
        if ret != 0 { return Err(InputTooLongError::new(0)); }

        // input and output cannot overlap
        // vec can return OOM which will result in crash, alloca can technically also corrupt stack
        // but all encryptions happen in UDP packets, which is at most MTU, so lets say 1500 bytes
        // so its totally safe
        let ret = alloca::with_alloca(in_out.input().len(), |uninit| unsafe {
            use core::mem::MaybeUninit;

            let len = uninit.len();
            // initialize alloca buffer
            core::ptr::copy_nonoverlapping(in_out.input().as_ptr(), uninit.as_mut_ptr() as *mut u8, len);

            esp_idf_sys::mbedtls_chachapoly_update(
                ctx,
                in_out.len(),
                uninit.as_ptr() as *const u8,
                in_out.input().as_ptr() as *mut u8,
            )
        });

        if ret != 0 { return Err(InputTooLongError::new(0)); }

        let ret = esp_idf_sys::mbedtls_chachapoly_finish(ctx, tag.as_mut_ptr());
        if ret != 0 { return Err(InputTooLongError::new(0)); }
    }

    Ok(tag.into())
}

fn check_input_lengths(aad: Aad<&[u8]>, input: &[u8]) -> Result<(), InputTooLongError> {
    if input.len() > MAX_IN_OUT_LEN {
        return Err(InputTooLongError::new(input.len()));
    }

    // RFC 8439 Section 2.8 says the maximum AAD length is 2**64 - 1, which is
    // never larger than usize::MAX, so we don't need an explicit length
    // check.
    const _USIZE_BOUNDED_BY_U64: u64 = u64_from_usize(usize::MAX);
    let _ = aad;

    Ok(())
}

// Also used by chacha20_poly1305_openssh.
pub(super) fn begin(
    key: &chacha::Key,
    nonce: Nonce,
    aad: Aad<&[u8]>,
    input: &[u8],
    cpu: cpu::Features,
) -> Result<(Counter, poly1305::Key), InputTooLongError> {
    check_input_lengths(aad, input)?;

    let mut key_bytes = [0u8; poly1305::KEY_LEN];
    let counter = key.encrypt_single_block_with_ctr_0(nonce, &mut key_bytes, cpu);
    let poly1305_key = poly1305::Key::new(key_bytes);
    Ok((counter, poly1305_key))
}

fn finish(auth: poly1305::Context, aad_len: usize, in_out_len: usize) -> Tag {
    let mut block = [0u8; poly1305::BLOCK_LEN];
    let (alen, clen) = block.split_at_mut(poly1305::BLOCK_LEN / 2);
    alen.copy_from_slice(&u64::to_le_bytes(u64_from_usize(aad_len)));
    clen.copy_from_slice(&u64::to_le_bytes(u64_from_usize(in_out_len)));
    auth.finish(&block)
}

#[inline]
fn poly1305_update_padded_16(ctx: &mut poly1305::Context, input: &[u8]) {
    let (whole, remainder) = input.as_chunks();
    ctx.update(whole);
    if !remainder.is_empty() {
        let mut block = [0u8; poly1305::BLOCK_LEN];
        sliceutil::overwrite_at_start(&mut block, remainder);
        ctx.update_block(block);
    }
}
