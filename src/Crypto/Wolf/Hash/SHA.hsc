{-# LANGUAGE DataKinds       #-}
{-# LANGUAGE EmptyDataDecls  #-}
{-# LANGUAGE QuasiQuotes     #-}
{-# LANGUAGE TemplateHaskell #-}
{-# LANGUAGE TypeFamilies    #-}


module Crypto.Wolf.Hash.SHA () where

import           Crypto.Hash.IO
import qualified Data.ByteString           as BS
import           Data.Monoid               ((<>))
import           Foreign.C.Types
import qualified Language.C.Inline         as C
import qualified Language.C.Inline.Unsafe  as CU
import           Data.Word (Word8, Word32)

import           Crypto.Wolf.Hash.Internal
import           Crypto.Wolf.Hash.Types

C.context (C.baseCtx <> C.fptrCtx <> wolfCryptCtx)

#define WC_NO_HARDEN
#define WOLFSSL_SHA224
#define WOLFSSL_SHA384
#define WOLFSSL_SHA512
#define WOLFSSL_SHA3

#define hs_Sha3_224 wc_Sha3
#define hs_Sha3_256 wc_Sha3
#define hs_Sha3_384 wc_Sha3
#define hs_Sha3_512 wc_Sha3

C.include "<wolfssl/wolfcrypt/hash.h>" 
#include <wolfssl/wolfcrypt/hash.h>

instance HashAlgorithm SHA1 where
  type HashBlockSize           SHA1 = (#const WC_SHA_BLOCK_SIZE)
  type HashDigestSize          SHA1 = (#const WC_SHA_DIGEST_SIZE)
  type HashInternalContextSize SHA1 = (#size wc_Sha)
  hashBlockSize  _          = (#const WC_SHA_BLOCK_SIZE)
  hashDigestSize _          = (#const WC_SHA_DIGEST_SIZE)
  hashInternalContextSize _ = (#size wc_Sha)
  hashInternalInit = hInit $ \fctx -> [CU.exp|
    int{ wc_InitSha( $fptr-ptr:(wc_Sha *fctx))}
    |]

  hashInternalUpdate = hUpdate $ \fctx fptr n32 -> [CU.exp| 
    int{ wc_ShaUpdate( $fptr-ptr:(wc_Sha *fctx) , $fptr-ptr:(byte *fptr) , $(word32 n32) ) }
    |]

  hashInternalFinalize = hFinalise $ \fctx fdig -> [CU.exp|
    int{ wc_ShaFinal( $fptr-ptr:(wc_Sha *fctx) , $fptr-ptr:(byte *fdig) ) } 
    |]

instance HashAlgorithm SHA224 where
  type HashBlockSize           SHA224 = (#const WC_SHA224_BLOCK_SIZE)
  type HashDigestSize          SHA224 = (#const WC_SHA224_DIGEST_SIZE)
  type HashInternalContextSize SHA224 = (#size wc_Sha224)
  hashBlockSize  _          = (#const WC_SHA224_BLOCK_SIZE)
  hashDigestSize _          = (#const WC_SHA224_DIGEST_SIZE)
  hashInternalContextSize _ = (#size wc_Sha224)
  hashInternalInit = hInit $ \fctx -> [CU.exp|
    int{ wc_InitSha224( $fptr-ptr:(wc_Sha224 *fctx))}
    |]

  hashInternalUpdate = hUpdate $ \fctx fptr n32 -> [CU.exp| 
    int{ wc_Sha224Update( $fptr-ptr:(wc_Sha224 *fctx) , $fptr-ptr:(byte *fptr) , $(word32 n32) ) }
    |]

  hashInternalFinalize = hFinalise $ \fctx fdig -> [CU.exp|
    int{ wc_Sha224Final( $fptr-ptr:(wc_Sha224 *fctx) , $fptr-ptr:(byte *fdig) ) } 
    |]

instance HashAlgorithm SHA256 where
  type HashBlockSize           SHA256 = (#const WC_SHA256_BLOCK_SIZE)
  type HashDigestSize          SHA256 = (#const WC_SHA256_DIGEST_SIZE)
  type HashInternalContextSize SHA256 = (#size wc_Sha256)
  hashBlockSize  _          = (#const WC_SHA256_BLOCK_SIZE)
  hashDigestSize _          = (#const WC_SHA256_DIGEST_SIZE)
  hashInternalContextSize _ = (#size wc_Sha256)
  hashInternalInit = hInit $ \fctx -> [CU.exp|
    int{ wc_InitSha256( $fptr-ptr:(wc_Sha256 *fctx))}
    |]

  hashInternalUpdate = hUpdate $ \fctx fptr n32 -> [CU.exp| 
    int{ wc_Sha256Update( $fptr-ptr:(wc_Sha256 *fctx) , $fptr-ptr:(byte *fptr) , $(word32 n32) ) }
    |]

  hashInternalFinalize = hFinalise $ \fctx fdig -> [CU.exp|
    int{ wc_Sha256Final( $fptr-ptr:(wc_Sha256 *fctx) , $fptr-ptr:(byte *fdig) ) } 
    |]

instance HashAlgorithm SHA384 where
  type HashBlockSize           SHA384 = (#const WC_SHA384_BLOCK_SIZE)
  type HashDigestSize          SHA384 = (#const WC_SHA384_DIGEST_SIZE)
  type HashInternalContextSize SHA384 = (#size wc_Sha384)
  hashBlockSize  _          = (#const WC_SHA384_BLOCK_SIZE)
  hashDigestSize _          = (#const WC_SHA384_DIGEST_SIZE)
  hashInternalContextSize _ = (#size wc_Sha384)
  hashInternalInit = hInit $ \fctx -> [CU.exp|
    int{ wc_InitSha384( $fptr-ptr:(wc_Sha384 *fctx))}
    |]

  hashInternalUpdate = hUpdate $ \fctx fptr n32 -> [CU.exp| 
    int{ wc_Sha384Update( $fptr-ptr:(wc_Sha384 *fctx) , $fptr-ptr:(byte *fptr) , $(word32 n32) ) }
    |]

  hashInternalFinalize = hFinalise $ \fctx fdig -> [CU.exp|
    int{ wc_Sha384Final( $fptr-ptr:(wc_Sha384 *fctx) , $fptr-ptr:(byte *fdig) ) } 
    |]

instance HashAlgorithm SHA512 where
  type HashBlockSize           SHA512 = (#const WC_SHA512_BLOCK_SIZE)
  type HashDigestSize          SHA512 = (#const WC_SHA512_DIGEST_SIZE)
  type HashInternalContextSize SHA512 = (#size wc_Sha512)
  hashBlockSize  _          = (#const WC_SHA512_BLOCK_SIZE)
  hashDigestSize _          = (#const WC_SHA512_DIGEST_SIZE)
  hashInternalContextSize _ = (#size wc_Sha512)
  hashInternalInit = hInit $ \fctx -> [CU.exp|
    int{ wc_InitSha512( $fptr-ptr:(wc_Sha512 *fctx))}
    |]

  hashInternalUpdate = hUpdate $ \fctx fptr n32 -> [CU.exp| 
    int{ wc_Sha512Update( $fptr-ptr:(wc_Sha512 *fctx) , $fptr-ptr:(byte *fptr) , $(word32 n32) ) }
    |]

  hashInternalFinalize = hFinalise $ \fctx fdig -> [CU.exp|
    int{ wc_Sha512Final( $fptr-ptr:(wc_Sha512 *fctx) , $fptr-ptr:(byte *fdig) ) } 
    |]

instance HashAlgorithm SHA3_224 where
  type HashBlockSize           SHA3_224 = (#const WC_SHA3_224_BLOCK_SIZE)
  type HashDigestSize          SHA3_224 = (#const WC_SHA3_224_DIGEST_SIZE)
  type HashInternalContextSize SHA3_224 = (#size wc_Sha3)
  hashBlockSize  _          = (#const WC_SHA3_224_BLOCK_SIZE)
  hashDigestSize _          = (#const WC_SHA3_224_DIGEST_SIZE)
  hashInternalContextSize _ = (#size wc_Sha3)
  hashInternalInit = hInit $ \fctx -> [CU.exp|
    int{ wc_InitSha3_224( $fptr-ptr:(hs_Sha3_224 *fctx), NULL, 0)}
    |]

  hashInternalUpdate = hUpdate $ \fctx fptr n32 -> [CU.exp| 
    int{ wc_Sha3_224_Update( $fptr-ptr:(hs_Sha3_224 *fctx) , $fptr-ptr:(byte *fptr) , $(word32 n32) ) }
    |]

  hashInternalFinalize = hFinalise $ \fctx fdig -> [CU.exp|
    int{ wc_Sha3_224_Final( $fptr-ptr:(hs_Sha3_224 *fctx) , $fptr-ptr:(byte *fdig) ) } 
    |]

instance HashAlgorithm SHA3_256 where
  type HashBlockSize           SHA3_256 = (#const WC_SHA3_256_BLOCK_SIZE)
  type HashDigestSize          SHA3_256 = (#const WC_SHA3_256_DIGEST_SIZE)
  type HashInternalContextSize SHA3_256 = (#size wc_Sha3)
  hashBlockSize  _          = (#const WC_SHA3_256_BLOCK_SIZE)
  hashDigestSize _          = (#const WC_SHA3_256_DIGEST_SIZE)
  hashInternalContextSize _ = (#size wc_Sha3)
  hashInternalInit = hInit $ \fctx -> [CU.exp|
    int{ wc_InitSha3_256( $fptr-ptr:(hs_Sha3_256 *fctx), NULL, 0)}
    |]

  hashInternalUpdate = hUpdate $ \fctx fptr n32 -> [CU.exp| 
    int{ wc_Sha3_256_Update( $fptr-ptr:(hs_Sha3_256 *fctx) , $fptr-ptr:(byte *fptr) , $(word32 n32) ) }
    |]

  hashInternalFinalize = hFinalise $ \fctx fdig -> [CU.exp|
    int{ wc_Sha3_256_Final( $fptr-ptr:(hs_Sha3_256 *fctx) , $fptr-ptr:(byte *fdig) ) } 
    |]

instance HashAlgorithm SHA3_384 where
  type HashBlockSize           SHA3_384 = (#const WC_SHA3_384_BLOCK_SIZE)
  type HashDigestSize          SHA3_384 = (#const WC_SHA3_384_DIGEST_SIZE)
  type HashInternalContextSize SHA3_384 = (#size wc_Sha3)
  hashBlockSize  _          = (#const WC_SHA3_384_BLOCK_SIZE)
  hashDigestSize _          = (#const WC_SHA3_384_DIGEST_SIZE)
  hashInternalContextSize _ = (#size wc_Sha3)
  hashInternalInit = hInit $ \fctx -> [CU.exp|
    int{ wc_InitSha3_384( $fptr-ptr:(hs_Sha3_384 *fctx), NULL, 0)}
    |]

  hashInternalUpdate = hUpdate $ \fctx fptr n32 -> [CU.exp| 
    int{ wc_Sha3_384_Update( $fptr-ptr:(hs_Sha3_384 *fctx) , $fptr-ptr:(byte *fptr) , $(word32 n32) ) }
    |]

  hashInternalFinalize = hFinalise $ \fctx fdig -> [CU.exp|
    int{ wc_Sha3_384_Final( $fptr-ptr:(hs_Sha3_384 *fctx) , $fptr-ptr:(byte *fdig) ) } 
    |]

instance HashAlgorithm SHA3_512 where
  type HashBlockSize           SHA3_512 = (#const WC_SHA3_512_BLOCK_SIZE)
  type HashDigestSize          SHA3_512 = (#const WC_SHA3_512_DIGEST_SIZE)
  type HashInternalContextSize SHA3_512 = (#size wc_Sha3)
  hashBlockSize  _          = (#const WC_SHA3_512_BLOCK_SIZE)
  hashDigestSize _          = (#const WC_SHA3_512_DIGEST_SIZE)
  hashInternalContextSize _ = (#size wc_Sha3)
  hashInternalInit = hInit $ \fctx -> [CU.exp|
    int{ wc_InitSha3_512( $fptr-ptr:(hs_Sha3_512 *fctx), NULL, 0)}
    |]

  hashInternalUpdate = hUpdate $ \fctx fptr n32 -> [CU.exp| 
    int{ wc_Sha3_512_Update( $fptr-ptr:(hs_Sha3_512 *fctx) , $fptr-ptr:(byte *fptr) , $(word32 n32) ) }
    |]

  hashInternalFinalize = hFinalise $ \fctx fdig -> [CU.exp|
    int{ wc_Sha3_512_Final( $fptr-ptr:(hs_Sha3_512 *fctx) , $fptr-ptr:(byte *fdig) ) } 
    |]