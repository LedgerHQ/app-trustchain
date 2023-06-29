/*****************************************************************************
 *   Ledger App Boilerplate.
 *   (c) 2020 Ledger SAS.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *****************************************************************************/

#include <stdint.h>   // uint*_t
#include <string.h>   // memset, explicit_bzero
#include <stdbool.h>  // bool

#include "crypto.h"
#include "globals.h"
#include "debug.h"

int crypto_derive_private_key(cx_ecfp_private_key_t *private_key,
                              uint8_t chain_code[static 32],
                              const uint32_t *bip32_path,
                              uint8_t bip32_path_len) {
    uint8_t raw_private_key[32] = {0};
    int error = 0;

    BEGIN_TRY {
        TRY {
            // derive the seed with bip32_path
            os_perso_derive_node_bip32(CX_CURVE_256K1,
                                       bip32_path,
                                       bip32_path_len,
                                       raw_private_key,
                                       chain_code);
            // new private_key from raw
            cx_ecfp_init_private_key(CX_CURVE_256K1,
                                     raw_private_key,
                                     sizeof(raw_private_key),
                                     private_key);
        }
        CATCH_OTHER(e) {
            error = e;
        }
        FINALLY {
            explicit_bzero(&raw_private_key, sizeof(raw_private_key));
        }
    }
    END_TRY;

    return error;
}

void crypto_init_public_key(cx_ecfp_private_key_t *private_key,
                            cx_ecfp_public_key_t *public_key,
                            uint8_t raw_public_key[static 64]) {
    // generate corresponding public key
    cx_ecfp_generate_pair(CX_CURVE_256K1, public_key, private_key, 1);
    memmove(raw_public_key, public_key->W + 1, 64);
}

int crypto_compress_public_key(const uint8_t *public_key, uint8_t compressed_public_key[static 33]) {
    for (int i = 0; i < 32; i++) {
       compressed_public_key[1 + i] = public_key[i + 1];
    }
    compressed_public_key[0] = (public_key[64] & 1) ? 0x03 : 0x02;
    return 0;
}

static int ecpoint_decompress(uint8_t prefix, uint8_t *raw_x, uint8_t *out_y) {
    /*
        # prime p = 2^256 - 2^32 - 2^9 - 2^8 - 2^7 - 2^6 - 2^4 - 1
        p = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f

        # bitcoin's compressed public key of private key 55255657523dd1c65a77d3cb53fcd050bf7fc2c11bb0bb6edabdbd41ea51f641
        compressed_key = '0229adfda789e1cad27b3c4084cccb30f48bc3dc56b2a368ae61dd895980a6d2d8'

        y_parity = int(compressed_key[:2]) - 2
        x = int(compressed_key[2:], 16)

        a = (pow_mod(x, 3, p) + 7) % p
        y = pow_mod(a, (p+1)//4, p)

        if y % 2 != y_parity:
            y = -y % p
    */
   /*
   const sqrt = (n: bigint) => {                           // √n = n^((p+1)/4) for fields p = 3 mod 4
  let r = 1n;     // So, a special, fast case. Paper: "Square Roots from 1;24,51,10 to Dan Shanks".
  for (let num = n, e = (P + 1n) / 4n; e > 0n; e >>= 1n) { // powMod: modular exponentiation.
    if (e & 1n) r = (r * num) % P;                      // Uses exponentiation by squaring.
    num = (num * num) % P;                              // Not constant-time.
  }
  return mod(r * r) === n ? r : err('sqrt invalid');    // check if result is valid
};
    const crv = (x: bigint) => mod(mod(x * x) * x + CURVE.b); 
     if (len === 33 && [0x02, 0x03].includes(head)) {    // compressed points: 33b, start
      if (!fe(x)) err('Point hex invalid: x not FE');   // with byte 0x02 or 0x03. Check if 0<x<P
      let y = sqrt(crv(x));                             // x³ + ax + b is right side of equation
      const isYOdd = (y & 1n) === 1n;                   // y² is equivalent left-side. Calculate y²:
      const headOdd = (head & 1) === 1;                 // y = √y²; there are two solutions: y, -y
      if (headOdd !== isYOdd) y = mod(-y);              // determine proper solution
      p = new Point(x, y, 1n);                          // create point
    }                 
   */
    // TODO REMOVE THIS FUNCTION AND USE BOLOS API
    uint8_t raw_p[] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                       0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                       0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFC, 0x2F};
    uint8_t raw_p_plus_one_div_4[] = {0x3f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                                      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                                      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xbf, 0xff, 0xff, 0x0c};
    cx_bn_t p;
    cx_bn_t p_plus_one_div_4;
    cx_bn_t x;
    cx_bn_t y_square;
    cx_bn_t y_square_square_root;
    cx_bn_t constant;
    cx_bn_t swap;
    uint8_t raw_zero = 0;
    uint8_t raw_seven = 7;
    uint8_t exponent = 3;
    bool is_odd;
    int ret = 0;


    BEGIN_TRY {
        TRY {
            cx_bn_lock(32, 0);

            // y_square = 0
            cx_bn_alloc(&y_square, 32);

            // y_square_square_root = 0
            cx_bn_alloc(&y_square_square_root, 32);

            // x = raw_x
            cx_bn_alloc_init(&x, 32, raw_x, 32);

            // init p
            cx_bn_alloc_init(&p, 32, raw_p, sizeof(raw_p));

            // init constant to 7
            cx_bn_alloc_init(&constant, 32, &raw_seven, sizeof(raw_seven));
            
            // (pow_mod(x, 3, p) + 7) % p
            //  -> y_square = pow_mod(x, 3, p)
            cx_bn_mod_pow(y_square, x, &exponent, sizeof(exponent), p);
              
            // -> y_square = y_square + 7
            cx_bn_add(y_square, y_square, constant);
            
            // -> y_square = y_square % p
            cx_bn_reduce(y_square_square_root, y_square, p);
            
            // Swap y_square_square_root and y_square otherwise y_square is equal to 0
            swap = y_square_square_root;
            y_square_square_root = y_square;
            y_square = swap;

            DEBUG_PRINT_BN("A: ", y_square)
            
            // y = pow_mod(y_square, (p+1)/4, p)
            cx_bn_destroy(&constant);
            cx_bn_alloc_init(&constant, 32, raw_p_plus_one_div_4, sizeof(raw_p_plus_one_div_4)); // Alloc constant to (p + 1) / 4
            DEBUG_PRINT_BN("P+1/4: ", constant)
            cx_bn_mod_pow_bn(y_square_square_root, y_square, constant, p);
            DEBUG_PRINT_BN("Y: ", y_square_square_root)
            
            // Check parity
            cx_bn_is_odd(y_square_square_root, &is_odd);
            
            // prefix == "02" and y_square_square_root & 1) or (prefix == "03" and not y_square_square_root & 1
            if ((prefix == 0x02 && is_odd) || (prefix == 0x03 && !is_odd)) {
                DEBUG_PRINT("ODD CHANGE\n")
                // y_square_square_root = -y_square_square_root % p
                cx_bn_destroy(&constant);
                cx_bn_alloc_init(&constant, 32, &raw_zero, sizeof(raw_zero)); // Alloc constant to 0
                cx_bn_mod_sub(y_square, constant, y_square_square_root, p);
                //APDU_LOG_BN(y_square)
                cx_bn_export(y_square, out_y, 32);
            } else {
                DEBUG_PRINT("NO CHANGE\n")
                cx_bn_export(y_square_square_root, out_y, 32);
            }
            
        }
        CATCH_OTHER(e) {
            ret = e;
        }
        FINALLY {
            cx_bn_destroy(&constant);
            cx_bn_destroy(&y_square_square_root);
            cx_bn_destroy(&y_square);
            cx_bn_unlock();
            DEBUG_PRINT("BN UNLOCKED\n");
        }
    } END_TRY;
    return ret;
}

int crypto_decompress_public_key(const uint8_t *compressed_public_key, uint8_t public_key[static 65]) {
    int error = 0;
    DEBUG_PRINT("COMPRESSED: ")
    DEBUG_PRINT_BUF(compressed_public_key, 33)
    
    error = ecpoint_decompress(compressed_public_key[0], compressed_public_key + 1, public_key + 1 + 32);
    if (error != 0) {
        return error;
    } 
    memcpy(public_key + 1, compressed_public_key + 1, 32);
    public_key[0] = 0x04;
    DEBUG_PRINT("DECOMPRESSED: ")
    DEBUG_PRINT_BUF(public_key, 65)
    DEBUG_PRINT_BUF(&error, sizeof(error))

    return 0;
}

int crypto_sign_block(void) {
    cx_ecfp_private_key_t private_key = {0};
    uint8_t chain_code[32] = {0};
    uint32_t info = 0;
    int sig_len = 0;

    // Derive private key
    DEBUG_LOG_BUF("FINAL DERIVATION ON ", SEED_ID_PATH, sizeof(SEED_ID_PATH));
    int error = crypto_derive_private_key(&private_key,
                                          chain_code,
                                          SEED_ID_PATH,
                                          SEED_ID_PATH_LEN);
    DEBUG_LOG_BUF("ISSUER PRIVATE KEY", private_key.d, private_key.d_len);

    cx_ecfp_public_key_t pk;
    uint8_t PK[65];
    uint8_t CPK[33];
    crypto_init_public_key(&private_key, &pk, PK + 1);
    crypto_compress_public_key(PK, CPK);
    if (error != 0) {
        return error;
    }
    DEBUG_LOG_BUF("SIGN WITH: ", CPK, sizeof(CPK));
    DEBUG_LOG_BUF("HASH TO SIGN: ", G_context.stream.last_block_hash, sizeof(G_context.stream.last_block_hash));
    //APDU_LOG_BUF(G_context.stream.last_block_hash, sizeof(G_context.stream.last_block_hash));
    // Sign hash of last block
    BEGIN_TRY {
        TRY {
            sig_len = cx_ecdsa_sign(&private_key,
                                    CX_RND_RFC6979 | CX_LAST,
                                    CX_SHA256,
                                    G_context.stream.last_block_hash,
                                    sizeof(G_context.stream.last_block_hash),
                                    G_context.signer_info.signature,
                                    sizeof(G_context.signer_info.signature),
                                    &info);
        }
        CATCH_OTHER(e) {
            error = e;
        }
        FINALLY {
            explicit_bzero(&private_key, sizeof(private_key));
        }
    }
    END_TRY;

    if (error == 0) {
        G_context.signer_info.signature_len = sig_len;
        G_context.signer_info.v = (uint8_t) (info & CX_ECCINFO_PARITY_ODD);
    }

    return error;
}



/**
 * Perform ECDH between a private key and a compressed public key.
*/
int crypto_ecdh(const cx_ecfp_private_key_t *private_key,
                const uint8_t *compressed_public_key,
                uint8_t *secret) {
    DEBUG_PRINT("crypto_ecdh 1\n")
    int error = 0;
    uint8_t raw_public_key[65] = {0};
    if ((error = crypto_decompress_public_key(compressed_public_key, raw_public_key)) != 0) {
        return error;
    }
    DEBUG_PRINT("crypto_ecdh 2\n")
    DEBUG_LOG_BUF("PUB KEY ECDH: ", raw_public_key, 65)
    DEBUG_LOG_BUF("PRIV KEY ECDH: ", private_key->d, 32)
    BEGIN_TRY {
        TRY {
            cx_ecdh(private_key, CX_ECDH_X, raw_public_key, 65, secret, 32);
            DEBUG_PRINT("crypto_ecdh 3\n")
        }
        CATCH_OTHER(e) {
            DEBUG_PRINT_BUF((uint8_t *)&e, sizeof(e));
            error = e;
        }
        FINALLY {
            explicit_bzero(&raw_public_key, sizeof(raw_public_key));
        }
    }
    END_TRY;
    return error;
}

int crypto_ephemeral_ecdh(const uint8_t *recipient_public_key, uint8_t *out_ephemeral_public_key, uint8_t *secret) {
    DEBUG_PRINT("crypto_ephemeral_ecdh 1\n")
    // Generate ephemeral keypair
    int ret = 0;
    cx_ecfp_private_key_t ephemeral_private_key;
    cx_ecfp_public_key_t ephemeral_public_key;


    ret = cx_ecfp_generate_pair(CX_CURVE_256K1, &ephemeral_public_key, &ephemeral_private_key, 0);
    if (ret != 0) {
        return ret;
    }

    DEBUG_PRINT("crypto_ephemeral_ecdh 2\n")
    DEBUG_PRINT_BUF(recipient_public_key, 33);
    // Perform ECDH between ephemeral private key and recipient public key
    ret = crypto_ecdh(&ephemeral_private_key, recipient_public_key, secret);
    if (ret != 0) {
        explicit_bzero(&ephemeral_private_key, sizeof(ephemeral_private_key));
        return ret;
    }

    DEBUG_PRINT("crypto_ephemeral_ecdh 3\n")
    // Compress ephemeral public key
    ret = crypto_compress_public_key(ephemeral_public_key.W, out_ephemeral_public_key);

    // Clean up
    explicit_bzero(&ephemeral_private_key, sizeof(ephemeral_private_key));
    return ret;
}