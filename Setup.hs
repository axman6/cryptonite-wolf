{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE CPP #-}
module Main where

import Control.Monad
import Distribution.Simple
import Distribution.System (OS(..), buildOS)
import Debug.Trace
import Distribution.Types.LocalBuildInfo
import System.Process (system)
import System.Directory

#define WOLFSSL_VERSION "5.1.1"

main = defaultMainWithHooks $
  simpleUserHooks
    { postConf = \ _args _configFlags _packageDescription localBuildInfo -> do
        case buildOS of
          Windows -> error "Build is not supported on Windows yet."
          _ -> do
            let sourcePath = "cbits/wolfssl-" <> WOLFSSL_VERSION <> "/src/.libs/libwolfssl.a"
            let destinationPath = buildDir localBuildInfo <> "/libwolfssl.a"
            doesFileExist ("cbits/wolfssl-" <> WOLFSSL_VERSION <> "/Makefile")
              >>= \case
                    True ->
                      doesFileExist sourcePath
                        >>= \case
                              True -> moveArchive sourcePath destinationPath
                              False -> do
                                build
                                moveArchive sourcePath destinationPath
                    False -> do
                      configure
                      build
                      moveArchive sourcePath destinationPath
    }

moveArchive :: FilePath -> FilePath -> IO ()
moveArchive source destination = void . system $ "cp -v " <> source <> " " <> destination

configure :: IO ()
configure = void . system $ "cd cbits/wolfssl-" <> WOLFSSL_VERSION <> " && ./configure --enable-static --enable-blake2 --enable-sha224 --enable-sha3 --enable-ripemd --enable-debug"

build :: IO ()
build = void . system $ "cd cbits/wolfssl-" <> WOLFSSL_VERSION <> " && make -j"
