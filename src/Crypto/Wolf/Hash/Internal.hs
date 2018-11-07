{-# LANGUAGE OverloadedLists   #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE QuasiQuotes       #-}
{-# LANGUAGE TemplateHaskell   #-}


module Crypto.Wolf.Hash.Internal where


import           Crypto.Hash               (Context, Digest)
import           Data.Monoid               ((<>))
import           Data.Word                 (Word32, Word8)
import           Foreign.ForeignPtr        (ForeignPtr, newForeignPtr_)
import           Foreign.Ptr               (FunPtr, Ptr)
import qualified Language.C.Inline.Context as C
import qualified Language.C.Inline.Unsafe  as CU
import qualified Language.C.Types          as C

import           Crypto.Wolf.Hash.Types


wolfCryptCtx :: C.Context
wolfCryptCtx = C.bsCtx <> C.vecCtx <> ctx
  where
    ctx = mempty { C.ctxTypesTable = openCvTypesTable }

openCvTypesTable :: C.TypesTable
openCvTypesTable =
  [ ( C.TypeName "byte"          , [t| Word8 |] )
  , ( C.TypeName "word32"        , [t| Word32 |] )
  , ( C.TypeName "wc_Sha"        , [t| Context SHA1 |] )
  , ( C.TypeName "wc_Sha224"     , [t| Context SHA224 |] )
  , ( C.TypeName "wc_Sha256"     , [t| Context SHA256 |] )
  , ( C.TypeName "wc_Sha384"     , [t| Context SHA384 |] )
  , ( C.TypeName "wc_Sha512"     , [t| Context SHA512 |] )
  , (C.TypeName "hs_Sha3_224"    , [t| Context SHA3_224 |])
  , (C.TypeName "hs_Sha3_256"    , [t| Context SHA3_256 |])
  , (C.TypeName "hs_Sha3_384"    , [t| Context SHA3_384 |])
  , (C.TypeName "hs_Sha3_512"    , [t| Context SHA3_512 |])
  , (C.TypeName "Md2"            , [t| Context MD2 |])
  , (C.TypeName "Md4"            , [t| Context MD4 |])
  , (C.TypeName "wc_Md5"         , [t| Context MD5 |])
  , (C.TypeName "hs_BLAKE2_160"  , [t| Context Blake2b_160 |])
  , (C.TypeName "hs_BLAKE2_224"  , [t| Context Blake2b_224 |])
  , (C.TypeName "hs_BLAKE2_256"  , [t| Context Blake2b_256 |])
  , (C.TypeName "hs_BLAKE2_384"  , [t| Context Blake2b_384 |])
  , (C.TypeName "hs_BLAKE2_512"  , [t| Context Blake2b_512 |])
  , (C.TypeName "RipeMd"         , [t| Context RIPEMD160 |])


  ]



hInit :: (ForeignPtr (Context a) -> IO b) -> Ptr (Context a) -> IO ()
hInit f ctx = do
  fctx <- newForeignPtr_ ctx
  _ <- f fctx
  pure ()

hUpdate :: (ForeignPtr (Context a) -> ForeignPtr Word8 -> Word32 -> IO b)
          -> Ptr (Context a) -> Ptr Word8 -> Word32 -> IO ()
hUpdate f ctx ptr n = do
  fctx <- newForeignPtr_ ctx
  fptr <- newForeignPtr_ ptr
  let n32 = fromIntegral n
  _ <- f fctx fptr n32
  pure ()

hFinalise :: (ForeignPtr (Context a) -> ForeignPtr (Digest a) -> IO b)
          -> Ptr (Context a) -> Ptr (Digest a) -> IO ()
hFinalise f ctx dig = do
  fctx <- newForeignPtr_ ctx
  fdig <- newForeignPtr_ dig
  _ <- f fctx fdig
  pure ()
