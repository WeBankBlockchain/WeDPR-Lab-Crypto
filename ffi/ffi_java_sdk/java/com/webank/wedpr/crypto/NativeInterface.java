package com.webank.wedpr.crypto;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;


public class NativeInterface {

    // COMPONENT VERSION STRING
    public static String WEDPR_JAVA_SDK_CRYPTO_LIB_PATH;
    /**
     * The minimum length a prefix for a file has to have according to {@link
     * File#createTempFile(String, String)}}.
     */
    static {
        try {
            String osName = System.getProperty("os.name").toLowerCase();
            if (osName.contains("windows")) {
                WEDPR_JAVA_SDK_CRYPTO_LIB_PATH = "/WeDPR_dynamic_lib/ffi_java_sdk.dll";
            } else if (osName.contains("linux")) {
                WEDPR_JAVA_SDK_CRYPTO_LIB_PATH = "/WeDPR_dynamic_lib/libffi_java_sdk.so";
            } else if (osName.contains("mac")) {
                WEDPR_JAVA_SDK_CRYPTO_LIB_PATH =
                        "/WeDPR_dynamic_lib/libffi_java_sdk.dylib";
            } else {
                throw new IOException("Unsupported the operating system " + osName + ".");
            }
            NativeUtils.loadLibraryFromJar(WEDPR_JAVA_SDK_CRYPTO_LIB_PATH);
        } catch (IOException  e) {
            throw new RuntimeException(e);
        }
    }

    public static native CryptoResult secp256k1Sign(String priKeyHex, String message);
    public static native CryptoResult secp256k1verify(String pubKeyHex, String message, String signature);
    public static native CryptoResult secp256k1keyPair();
    public static native CryptoResult sm2Sign(String priKeyHex, String message);
    public static native CryptoResult sm2verify(String pubKeyHex, String message, String signature);
    public static native CryptoResult sm2keyPair();
    public static native CryptoResult keccak256(String messageHex);
    public static native CryptoResult sm3(String messageHex);
}


class NativeUtils {

    /**
     * The minimum length a prefix for a file has to have according to {@link
     * File#createTempFile(String, String)}}.
     */
    private static final int MIN_PREFIX_LENGTH = 3;

    public static final String NATIVE_FOLDER_PATH_PREFIX = "nativeutils";

    /** Temporary directory which will contain the .so file. */
    private static File temporaryDir;

    /** Private constructor - this class will never be instanced */
    private NativeUtils() {}

    /**
     * The file from JAR is copied into system temporary directory and then loaded. The temporary
     * file is deleted after exiting.
     *
     * @param path
     * @throws IOException
     * @throws FileNotFoundException
     */
    public static synchronized void loadLibraryFromJar(String path) throws IOException {

        if (null == path || !path.startsWith("/")) {
            throw new IllegalArgumentException("The path has to be absolute (start with '/').");
        }

        // Obtain filename from path
        String[] parts = path.split("/");
        String filename = (parts.length > 1) ? parts[parts.length - 1] : null;

        if (filename == null || filename.length() < MIN_PREFIX_LENGTH) {
            throw new IllegalArgumentException(
                    "The filename has to be at least 3 characters long.");
        }

        // create temp file
        if (temporaryDir == null) {
            temporaryDir = createTempDirectory(NATIVE_FOLDER_PATH_PREFIX);
            temporaryDir.deleteOnExit();
        }
        File temp = new File(temporaryDir, filename);

        // copy file from jar package to temp directory
        try (InputStream is = NativeUtils.class.getResourceAsStream(path)) {
            Files.copy(is, temp.toPath(), StandardCopyOption.REPLACE_EXISTING);
        } catch (IOException e) {
            temp.delete();
            throw e;
        } catch (NullPointerException e) {
            temp.delete();
            throw new FileNotFoundException("File " + path + " was not found inside JAR.");
        }

        // load the library
        try {
            System.load(temp.getAbsolutePath());
        } finally {
            temp.deleteOnExit();
        }
    }

    /**
     * Prepare temporary file
     *
     * @param prefix
     * @return
     * @throws IOException
     */
    private static File createTempDirectory(String prefix) throws IOException {
        String tempDir = System.getProperty("java.io.tmpdir");
        File generatedDir = new File(tempDir, prefix + System.nanoTime());

        if (!generatedDir.mkdir()) {
            throw new IOException("Failed to create temp directory " + generatedDir.getName());
        }
        return generatedDir;
    }
}
