#!/usr/bin/env python3
"""Exercise real JVM exception paths against a built binary JNI library."""
import argparse
from pathlib import Path
import subprocess
import tempfile

parser = argparse.ArgumentParser()
parser.add_argument("--library", type=Path, required=True)
parser.add_argument("--java-home", type=Path, required=True)
parser.add_argument("--bytebuffer-library", type=Path)
args = parser.parse_args()
library = args.library.resolve(strict=True)
java = args.java_home / "bin" / "java"
javac = args.java_home / "bin" / "javac"

source = r"""
package com.webank.wedpr.crypto;
import java.util.Arrays;
import java.nio.ByteBuffer;
public class NativeInterface {
    public static native ByteBuffer copyBuffer();
    public static native Object aes256Encrypt(byte[] message, byte[] key, byte[] iv);
    public static native Object aes256Decrypt(byte[] ciphertext, byte[] key, byte[] iv);
    public static void main(String[] args) throws Exception {
        System.load(args[0]);
        byte[] message = new byte[] {1, 2, 3};
        byte[] key = new byte[32];
        byte[] iv = new byte[16];
        if (!args[1].equals("normal")) {
            try {
                aes256Encrypt(message, key, iv);
                throw new AssertionError("Expected a Java linkage exception");
            } catch (NoClassDefFoundError | NoSuchFieldError expected) {
                System.out.println(args[1] + ": Java exception preserved; JVM survived");
                return;
            }
        }
        Object encrypted = aes256Encrypt(message, key, iv);
        byte[] ciphertext = (byte[]) encrypted.getClass().getField("encryptedData").get(encrypted);
        Object decrypted = aes256Decrypt(ciphertext, key, iv);
        byte[] recovered = (byte[]) decrypted.getClass().getField("decryptedData").get(decrypted);
        if (!Arrays.equals(message, recovered)) throw new AssertionError("round trip failed");
        ciphertext[8] ^= 1;
        Object rejected = aes256Decrypt(ciphertext, key, iv);
        if (rejected == null || rejected.getClass().getField("wedprErrorMessage").get(rejected) == null)
            throw new AssertionError("tampered ciphertext must return an error");
        if (rejected.getClass().getField("decryptedData").get(rejected) != null)
            throw new AssertionError("failed authentication released plaintext");
        Object invalidKey = aes256Encrypt(message, new byte[1], iv);
        String error = (String) invalidKey.getClass().getField("wedprErrorMessage").get(invalidKey);
        if (error == null || error.contains(Arrays.toString(message)))
            throw new AssertionError("error diagnostics exposed plaintext");
        System.out.println("normal: round trip and authentication failure passed");
        if (args.length > 2) {
            System.load(args[2]);
            ByteBuffer retained = copyBuffer();
            if (retained == null || retained.isDirect() || retained.capacity() != 4096)
                throw new AssertionError("expected Java-owned heap buffer");
            for (int i = 0; i < 64; ++i) copyBuffer().put(0, (byte) 0x7f);
            System.gc();
            for (int i = 0; i < retained.capacity(); ++i)
                if (retained.get(i) != (byte) (i % 251))
                    throw new AssertionError("Rust mutation/free changed the Java buffer");
            retained.put(0, (byte) 42);
            if (retained.get(0) != 42) throw new AssertionError("buffer not writable");
            System.out.println("ByteBuffer: Java-owned data survived Rust mutation/free and GC");
        }
    }
}
"""

for mode in ("missing-class", "missing-field", "normal"):
    with tempfile.TemporaryDirectory(prefix="wedpr-jni-") as directory:
        root = Path(directory)
        package = root / "com" / "webank" / "wedpr" / "crypto"
        package.mkdir(parents=True)
        interface = package / "NativeInterface.java"
        interface.write_text(source)
        files = [str(interface)]
        if mode != "missing-class":
            fields = "" if mode == "missing-field" else (
                "public byte[] encryptedData; public byte[] decryptedData; "
                "public String wedprErrorMessage;"
            )
            result = package / "CryptoResult.java"
            result.write_text("package com.webank.wedpr.crypto; public class CryptoResult {" + fields + "}")
            files.append(str(result))
        subprocess.run([str(javac), "-d", str(root), *files], check=True, timeout=30)
        extra = [str(args.bytebuffer_library.resolve(strict=True))] if args.bytebuffer_library else []
        subprocess.run([str(java), "-cp", str(root), "com.webank.wedpr.crypto.NativeInterface",
                        str(library), mode, *extra], check=True, timeout=30, cwd=root)
