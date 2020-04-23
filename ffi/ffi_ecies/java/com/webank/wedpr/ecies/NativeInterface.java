package com.webank.wedpr.ecies;

import com.webank.wedpr.common.CompatibleResult;
import com.webank.wedpr.common.NativeUtils;
import com.webank.wedpr.common.Utils;
import com.webank.wedpr.common.WedprException;
import java.io.IOException;

public class NativeInterface {

    // COMPONENT VERSION STRING
    public static final String VERSION = "v0.1-generic";
    public static String WEDPR_ECIES_LIB_PATH;

    static {
        try {
            String osName = System.getProperty("os.name").toLowerCase();
            if (osName.contains("windows")) {
                WEDPR_ECIES_LIB_PATH = "/WeDPR_dynamic_lib/ffi_ecies.dll";
            } else if (osName.contains("linux")) {
                WEDPR_ECIES_LIB_PATH = "/WeDPR_dynamic_lib/libffi_ecies.so";
            } else if (osName.contains("mac")) {
                WEDPR_ECIES_LIB_PATH =
                        "/WeDPR_dynamic_lib/libffi_ecies.dylib";
            } else {
                throw new WedprException("Unsupported the operating system " + osName + ".");
            }
            NativeUtils.loadLibraryFromJar(WEDPR_ECIES_LIB_PATH);
        } catch (IOException | WedprException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     *
     * @param pubKey Hex Format String
     * @param message Hex Format String
     * @return Object EciesResult
     */
    public static native EciesResult eciesEncrypt(String pubKey, String message);

    /**
     *
     * @param priKey Hex Format String
     * @param encryptMessage Hex Format String
     * @return Object EciesResult
     */
    public static native EciesResult eciesDecrypt(String priKey, String encryptMessage);
}
