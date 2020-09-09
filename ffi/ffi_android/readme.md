# how to cross compile with openssl

for android, my ndk is 23

zshrc

```bash
# export PATH="/usr/local/opt/openssl/bin:$PATH"
# export LDFLAGS="-L/usr/local/opt/openssl/lib"
# export CPPFLAGS="-I/usr/local/opt/openssl/include"
# export PKG_CONFIG_PATH="/usr/local/opt/openssl/lib/pkgconfig"
export LDFLAGS="-L/Users/asher/Downloads/openssl.1.0.2k_for_android_ios/android/openssl-arm64-v8a/lib"
export CPPFLAGS="-I/Users/asher/Downloads/openssl.1.0.2k_for_android_ios/android/openssl-arm64-v8a/include"
export PKG_CONFIG_PATH="/usr/local/opt/openssl/lib/pkgconfig"
export PKG_CONFIG_ALLOW_CROSS=1
export OPENSSL_STATIC=1
```

```bash
export ANDROID_NDK_HOME=/Users/asher/Library/Android/sdk/ndk/21.3.6528147

/Users/asher/Library/Android/sdk/ndk/21.3.6528147cd
```

for ios, use local openssl is fine.