/* key_data.c
 *
 * Copyright (C) 2006-2021 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * wolfSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

#include "key_data.h"

/*-------------------------------------------------------------------------
      TSIP v1.09 or later
--------------------------------------------------------------------------*/
#if defined(WOLFSSL_RENESAS_TSIP_TLS) && (WOLFSSL_RENESAS_TSIP_VER >=109)

const st_key_block_data_t g_key_block_data =
{
    /* uint8_t encrypted_provisioning_key[R_TSIP_AES_CBC_IV_BYTE_SIZE * 2]; */
    {
        0xD8, 0xB3, 0xA7, 0xDB, 0xD1, 0x5E, 0x44, 0x24, 0x00, 0xDA, 0xEB, 0xB3,
        0x33, 0xE1, 0x49, 0xAF, 0x4B, 0xAC, 0xC5, 0xF5, 0xC8, 0xD5, 0xAC, 0x12,
        0x7F, 0xF7, 0x58, 0xAE, 0x59, 0xFE, 0xFB, 0x32
    },
    /* uint8_t iv[R_TSIP_AES_CBC_IV_BYTE_SIZE]; */
    {
        0xF6, 0xA9, 0x83, 0x5A, 0xA1, 0x65, 0x1D, 0x28, 0xC8, 0x1A, 0xA6, 0x9D,
        0x34, 0xB2, 0x4D, 0x92
    },
    /* uint8_t 
     * encrypted_user_rsa2048_ne_key[R_TSIP_RSA2048_NE_KEY_BYTE_SIZE + 16];
     */
    {
        0xC1, 0xB7, 0xCC, 0x99, 0x0A, 0xC8, 0x3E, 0xAB, 0x74, 0x35, 0x9D, 0x1C,
        0x81, 0x32, 0x72, 0xA7, 0xA8, 0x0D, 0xBA, 0x1B, 0x35, 0x42, 0x2F, 0x7B,
        0xB4, 0x1C, 0x86, 0x81, 0xC4, 0xFA, 0xD9, 0x65, 0xCE, 0x8A, 0x70, 0x1A,
        0x28, 0x09, 0x72, 0xC0, 0x4F, 0x7A, 0x4A, 0xC7, 0xE6, 0x21, 0x65, 0x6E,
        0xEB, 0x11, 0x45, 0x23, 0x35, 0xC0, 0x0F, 0x1D, 0x48, 0xC6, 0x8A, 0x1C,
        0x27, 0x70, 0xA6, 0x26, 0xD0, 0x49, 0xCD, 0x42, 0x8D, 0x65, 0x2F, 0xFC,
        0x32, 0x12, 0x6F, 0xE6, 0x61, 0xB6, 0x2F, 0xD9, 0xA7, 0xC3, 0xB0, 0x3A,
        0x4F, 0x58, 0xFD, 0x1E, 0x8E, 0xDE, 0x5C, 0xD4, 0xF3, 0x4E, 0xF7, 0x45,
        0x01, 0xDC, 0x39, 0x38, 0x15, 0x37, 0x8A, 0xFD, 0x59, 0x1A, 0x6C, 0x04,
        0x55, 0x31, 0x56, 0x14, 0x07, 0x71, 0x9A, 0x19, 0x81, 0x7F, 0x69, 0x88,
        0xD7, 0xD5, 0xBE, 0xB4, 0x95, 0x83, 0xC5, 0x35, 0xA8, 0xDE, 0x65, 0x5E,
        0x95, 0xBB, 0xE3, 0x9C, 0x81, 0x4C, 0x8B, 0x18, 0x4C, 0xEA, 0x12, 0xEE,
        0xF3, 0x98, 0x68, 0x35, 0xC8, 0xA5, 0x69, 0x6F, 0x71, 0x8C, 0xAA, 0xB5,
        0x3F, 0xF7, 0x3C, 0x10, 0xC0, 0xD4, 0x46, 0x4D, 0xD0, 0x56, 0xDB, 0x7F,
        0xC1, 0x52, 0xE0, 0x06, 0xD8, 0xB9, 0x5E, 0x41, 0x43, 0x0E, 0xBB, 0xCD,
        0x5C, 0x4D, 0x02, 0x37, 0xD1, 0xFD, 0x88, 0xCB, 0x49, 0xC3, 0x51, 0x0C,
        0x8A, 0x17, 0x71, 0xFE, 0x97, 0x8F, 0xF6, 0x65, 0xFC, 0xF8, 0xB4, 0xC2,
        0x65, 0x4B, 0x5B, 0x74, 0x4B, 0xFF, 0x35, 0xE9, 0x33, 0x3A, 0xBE, 0xDF,
        0x23, 0x4F, 0xDB, 0x3F, 0x94, 0x6F, 0x34, 0x21, 0x76, 0x14, 0xAF, 0x2B,
        0x96, 0x62, 0xA5, 0x52, 0x80, 0xB9, 0x36, 0x7E, 0x25, 0xAF, 0xB6, 0x75,
        0xE5, 0x79, 0x8E, 0xE8, 0x67, 0xE4, 0xDD, 0x4B, 0x3D, 0xB2, 0x7F, 0xAF,
        0x32, 0xC5, 0xF5, 0x1B, 0x90, 0x0E, 0x41, 0x97, 0x5D, 0xFD, 0xC1, 0x9A,
        0xA1, 0xF9, 0x57, 0xF1, 0x21, 0x94, 0xF9, 0x31, 0xC9, 0xC7, 0x16, 0xAA,
        0xD8, 0xE9, 0x78, 0x03, 0xAD, 0xEF, 0x3E, 0x98, 0x1F, 0x32, 0x3D, 0x8E
    },
    /* uint8_t encrypted_user_update_key[R_TSIP_AES256_KEY_BYTE_SIZE + 16]; */
    {
        0x70, 0xA8, 0xB5, 0x63, 0xE9, 0xC2, 0xA0, 0xFC, 0xE5, 0xA5, 0x4D, 0x94,
        0x6E, 0x69, 0xE8, 0x94, 0xAC, 0xE6, 0x68, 0x7C, 0xB2, 0xB9, 0xDC, 0xCF,
        0x69, 0xBC, 0xE6, 0xB9, 0x8C, 0xDA, 0x72, 0x5C, 0x62, 0xE9, 0xB9, 0xC1,
        0xB4, 0xC7, 0x60, 0x21, 0xAE, 0x1B, 0x52, 0x25, 0x06, 0x8A, 0x91, 0xA1
    },

};

/* Public key type of CA root cert: 0: RSA-2048 2: ECDSA-P256*/
#if defined(USE_ECC_CERT)
const uint32_t              encrypted_user_key_type =
                                    R_TSIP_TLS_PUBLIC_KEY_TYPE_ECDSA_P256;
#else
const uint32_t              encrypted_user_key_type =
                                    R_TSIP_TLS_PUBLIC_KEY_TYPE_RSA2048;
#endif

const unsigned char ca_ecc_cert_der_sig[] =
{
    0x7D, 0x73, 0xF9, 0x15, 0x6A, 0x87, 0x5C, 0xE9, 0x36, 0x4B, 0xA5, 0x8B,
    0xE8, 0xC1, 0xBD, 0x78, 0x01, 0x51, 0x93, 0xC1, 0xAF, 0xF7, 0xCB, 0xE0,
    0x61, 0xD4, 0x33, 0x67, 0xEC, 0x6E, 0x37, 0x92, 0xE2, 0x16, 0x99, 0xC5,
    0x5E, 0x74, 0xB0, 0xF3, 0xFD, 0xE0, 0x13, 0x1C, 0xA0, 0x5D, 0x10, 0x41,
    0xE6, 0x8B, 0xAE, 0x48, 0xF5, 0x3E, 0x5E, 0xEA, 0xED, 0x17, 0x45, 0xD5,
    0xCA, 0xDC, 0xB4, 0xC6, 0xA5, 0xD7, 0x9E, 0xAA, 0x06, 0x99, 0xA2, 0x70,
    0x8C, 0x4C, 0xC0, 0x19, 0xB2, 0xF9, 0x6E, 0x1C, 0x96, 0x58, 0xE0, 0xFD,
    0x26, 0x02, 0x34, 0xA6, 0x1D, 0x4A, 0x03, 0x76, 0x3E, 0x84, 0x7A, 0xAA,
    0xB4, 0xBF, 0x1E, 0x5A, 0x77, 0x97, 0x12, 0x56, 0x23, 0x55, 0xF6, 0xC7,
    0xED, 0x61, 0x75, 0x42, 0x99, 0x67, 0xCD, 0x10, 0xCA, 0x79, 0x4E, 0x9A,
    0x91, 0x67, 0xCF, 0x49, 0x6F, 0xC1, 0xD2, 0x0C, 0x16, 0x90, 0xE4, 0x2E,
    0x27, 0x63, 0x13, 0xF9, 0x4F, 0x6C, 0xE3, 0x55, 0x09, 0x18, 0xC2, 0xB3,
    0x70, 0x5C, 0x0C, 0x52, 0x5B, 0xC4, 0x81, 0xFD, 0x30, 0xE9, 0x41, 0xB1,
    0x1C, 0x84, 0x07, 0x36, 0xFC, 0x2F, 0x68, 0x97, 0x2D, 0x73, 0x56, 0x88,
    0x39, 0x5C, 0x9E, 0x50, 0xA8, 0x47, 0x1E, 0x83, 0xF5, 0x4E, 0xD0, 0xA5,
    0xAD, 0xFA, 0xE0, 0x52, 0xFC, 0x47, 0x15, 0x58, 0x2E, 0xC5, 0x53, 0x0F,
    0x3F, 0x98, 0x11, 0xF3, 0x5C, 0x3A, 0x83, 0x35, 0xF7, 0x9E, 0x1B, 0x94,
    0x7A, 0x84, 0x7D, 0x51, 0x72, 0x32, 0xE2, 0x29, 0xF2, 0x9D, 0xC0, 0xED,
    0x25, 0x9A, 0xD6, 0x76, 0x07, 0x75, 0x18, 0xA8, 0x29, 0xAA, 0x2D, 0x69,
    0xE2, 0xAF, 0xEE, 0x03, 0xE9, 0xDC, 0xCC, 0x4E, 0x92, 0x71, 0x05, 0x3A,
    0x74, 0x4A, 0x21, 0xA4, 0x3B, 0xB3, 0xCF, 0x8A, 0x73, 0x02, 0x8C, 0x84,
    0x8B, 0x6B, 0xDA, 0x46
};
const int sizeof_ca_ecc_cert_sig = sizeof(ca_ecc_cert_der_sig);

/* ./ca-cert.der.sign,  */
const unsigned char ca_cert_der_sig[] =
{
	0x0E, 0xC3, 0x9B, 0x77, 0xF8, 0x58, 0x08, 0x9E, 0x5D, 0x1E, 0x03, 0x8D,
    0x60, 0xD1, 0xF6, 0x3E,	0x3D, 0xFF, 0x89, 0x4C, 0x91, 0x5C, 0x00, 0xEB,
    0x05, 0xE5, 0x65, 0x62, 0x17, 0xFB, 0xD4, 0x52,	0x69, 0x9D, 0xB8, 0x07,
    0xAF, 0xA9, 0x4C, 0xA5, 0xB9, 0x8D, 0x52, 0xC0, 0xF3, 0x34, 0x13, 0x67,
	0x40, 0xAA, 0xE1, 0xA3, 0x9E, 0x5D, 0x0F, 0xCE, 0x87, 0xB0, 0x10, 0xB4,
    0x79, 0x8F, 0x84, 0x21,	0x81, 0xC2, 0xF9, 0xF7, 0xDB, 0xCB, 0x8F, 0xE4,
    0x9B, 0xF5, 0x85, 0x9D, 0x11, 0x04, 0xFB, 0xA7,	0xFD, 0x13, 0x6F, 0x02,
    0xA5, 0xBF, 0xE0, 0x89, 0x62, 0x5E, 0x24, 0x95, 0xF6, 0x01, 0x7D, 0x7F,
	0xB5, 0xD1, 0xDD, 0xF3, 0x3B, 0xD5, 0x04, 0x54, 0xE1, 0x8E, 0xA8, 0x3D,
    0x30, 0xB3, 0x35, 0x76,	0xAF, 0xA7, 0x94, 0xD7, 0x59, 0x82, 0x38, 0x2C,
    0xD6, 0x95, 0x57, 0xD1, 0xD5, 0x62, 0xB1, 0x69,	0x60, 0xCD, 0x3F, 0x7D,
    0x0E, 0x9F, 0x00, 0x21, 0x04, 0xFE, 0x43, 0xBD, 0x7D, 0x3D, 0xA7, 0x6B,
	0xC5, 0x82, 0x92, 0xDE, 0xB7, 0xA3, 0xD4, 0x7D, 0x3C, 0x14, 0x46, 0x28,
    0x50, 0xCA, 0x86, 0x9F,	0x66, 0x4C, 0xB0, 0x46, 0x46, 0x4D, 0x31, 0xD6,
    0x7B, 0xEC, 0xBA, 0xED, 0xA1, 0xF9, 0x88, 0x68,	0xB9, 0xA9, 0xDA, 0x88,
    0x63, 0x01, 0x95, 0x5B, 0x78, 0x38, 0x03, 0xD6, 0xDF, 0x86, 0xC4, 0x3E,
	0x3B, 0xCF, 0xED, 0x8B, 0x2A, 0x41, 0x49, 0x65, 0x3E, 0x2F, 0x45, 0x71,
    0xD8, 0x0B, 0xF1, 0xF0,	0xC7, 0xB5, 0x2E, 0xBE, 0xF0, 0x71, 0xDE, 0x40,
    0xB0, 0x54, 0x25, 0xD7, 0x4A, 0x86, 0xF1, 0xB9,	0xF6, 0xAB, 0x07, 0x07,
    0x21, 0x7C, 0x15, 0x7B, 0x1F, 0xCF, 0xE4, 0x1F, 0x0B, 0xEB, 0x0E, 0x96,
	0xE5, 0x59, 0x34, 0xC6, 0x4B, 0x1B, 0xF6, 0xC7, 0x6C, 0x4C, 0x16, 0x43,
    0x72, 0xAF, 0x82, 0x1E
};
const int sizeof_ca_cert_sig = sizeof(ca_cert_der_sig);
/* ./client-cert.der.sign,  */
const unsigned char client_cert_der_sign[] =
{
        0x5D, 0x1F, 0x89, 0x41, 0xEC, 0x47, 0xC8, 0x90, 0x61, 0x79,
        0x8A, 0x16, 0x1F, 0x31, 0x96, 0x67, 0xD9, 0x3C, 0xEC, 0x6B,
        0x58, 0xC6, 0x5A, 0xED, 0x99, 0xB3, 0xEF, 0x27, 0x6F, 0x04,
        0x8C, 0xD9, 0x68, 0xB1, 0xD6, 0x23, 0x15, 0x84, 0x00, 0xE1,
        0x27, 0xD1, 0x1F, 0x68, 0xB7, 0x3F, 0x13, 0x53, 0x8A, 0x95,
        0x5A, 0x20, 0x7C, 0xB2, 0x76, 0x5B, 0xDC, 0xE0, 0xA6, 0x21,
        0x7C, 0x49, 0xCF, 0x93, 0xBA, 0xD5, 0x12, 0x9F, 0xEE, 0x90,
        0x5B, 0x3F, 0xA3, 0x9D, 0x13, 0x72, 0xAC, 0x72, 0x16, 0xFE,
        0x1D, 0xBE, 0xEB, 0x8E, 0xC7, 0xDC, 0xC4, 0xF8, 0x1A, 0xD8,
        0xA0, 0xA4, 0xF6, 0x04, 0x30, 0xF6, 0x7E, 0xB6, 0xC8, 0xE1,
        0xAB, 0x88, 0x37, 0x08, 0x63, 0x72, 0xAA, 0x46, 0xCC, 0xCA,
        0xF0, 0x9E, 0x02, 0x1E, 0x65, 0x67, 0xFF, 0x2C, 0x9D, 0x81,
        0x6C, 0x1E, 0xF1, 0x54, 0x05, 0x68, 0x68, 0x18, 0x72, 0x26,
        0x55, 0xB6, 0x2C, 0x95, 0xC0, 0xC9, 0xB2, 0xA7, 0x0B, 0x60,
        0xD7, 0xEB, 0x1D, 0x08, 0x1A, 0xA2, 0x54, 0x15, 0x89, 0xCB,
        0x83, 0x21, 0x5D, 0x15, 0x9B, 0x38, 0xAC, 0x89, 0x63, 0xD5,
        0x4B, 0xF4, 0x8B, 0x47, 0x93, 0x78, 0x43, 0xCB, 0x9B, 0x71,
        0xBF, 0x94, 0x76, 0xB5, 0xCE, 0x35, 0xA9, 0x1A, 0xD5, 0xA5,
        0xD8, 0x19, 0xA6, 0x04, 0x39, 0xB1, 0x09, 0x8C, 0x65, 0x02,
        0x58, 0x3A, 0x95, 0xEF, 0xA2, 0xC3, 0x85, 0x18, 0x61, 0x23,
        0x2D, 0xC5, 0xCD, 0x62, 0xC1, 0x19, 0x31, 0xE5, 0x36, 0x95,
        0x22, 0xDB, 0x3E, 0x1A, 0x3C, 0xE8, 0xC6, 0x2E, 0xDF, 0xD9,
        0x2F, 0x84, 0xC1, 0xF0, 0x38, 0x2B, 0xE5, 0x73, 0x35, 0x4F,
        0x05, 0xE2, 0xA5, 0x60, 0x79, 0xB0, 0x23, 0xDC, 0x56, 0x4C,
        0xE7, 0xD9, 0x1F, 0xCF, 0x6A, 0xFC, 0x55, 0xEB, 0xAA, 0x48,
        0x3E, 0x95, 0x2A, 0x10, 0x01, 0x05
};
const int sizeof_client_cert_der_sign = sizeof(client_cert_der_sign);

uint32_t s_inst1[R_TSIP_SINST_WORD_SIZE] = { 0 };
uint32_t s_inst2[R_TSIP_SINST2_WORD_SIZE]= { 0 };
#endif
