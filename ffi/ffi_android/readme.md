# how to cross compile with openssl

for android, my ndk version is 23

zshrc

```bash
# for ios
# export PATH="/usr/local/opt/openssl/bin:$PATH"
# export LDFLAGS="-L/usr/local/opt/openssl/lib"
# export CPPFLAGS="-I/usr/local/opt/openssl/include"
# export PKG_CONFIG_PATH="/usr/local/opt/openssl/lib/pkgconfig"
export LDFLAGS="-L/Users/asher/Downloads/openssl.1.0.2k_for_android_ios/android/openssl-arm64-v8a/lib"
export CPPFLAGS="-I/Users/asher/Downloads/openssl.1.0.2k_for_android_ios/android/openssl-arm64-v8a/include"
export PKG_CONFIG_PATH="/usr/local/opt/openssl/lib/pkgconfig"
export PKG_CONFIG_ALLOW_CROSS=1
# for android
export OPENSSL_STATIC=1
```

toolchain

```bash
rustup target add aarch64-apple-ios armv7-apple-ios armv7s-apple-ios x86_64-apple-ios i386-apple-ios
rustup target add aarch64-linux-android armv7-linux-androideabi i686-linux-android x86_64-linux-android
```

explain

```bash
rustup target add armv7-linux-androideabi   # for arm
rustup target add i686-linux-android        # for x86
rustup target add aarch64-linux-android     # for arm64
rustup target add x86_64-linux-android      # for x86_64
rustup target add x86_64-unknown-linux-gnu  # for linux-x86-64
rustup target add x86_64-apple-darwin       # for darwin (macOS)
rustup target add x86_64-pc-windows-gnu     # for win32-x86-64-gnu
rustup target add x86_64-pc-windows-msvc    # for win32-x86-64-msvc
```

rust link args

```bash
# some old phone need this option
export RUSTFLAGS="-C link-arg=-Wl,--hash-style=both"
```

```bash
# now use --android-platform 21
cargo ndk --target i686-linux-android --android-platform 26 -- build --release
# aarch64-linux-android
# armv7-linux-androideabi
# i686-linux-android
# target 21 is android 5.0, work fine in old oppo, 26 is too high run in old version
```

```bash
export ANDROID_NDK_HOME=/Users/asher/Library/Android/sdk/ndk/21.3.6528147

/Users/asher/Library/Android/sdk/ndk/21.3.6528147cd
```

for ios, local openssl work well.
