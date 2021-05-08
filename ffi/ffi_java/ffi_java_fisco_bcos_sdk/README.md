# ffi_java_fisco_bcos_sdk

```java
package com.webank.fisco.bcos.wedpr.sdk;

public class NativeInterface {
    public static native SdkResult curve25519VrfProveUtf8(String privateKey, String utf8Message);

    public static native SdkResult curve25519VrfProveFastUtf8(String privateKey, String publicKey, String utf8Message);

    public static native SdkResult curve25519VrfVerifyUtf8(String publicKey, String utf8Message, String proof);

    public static native SdkResult curve25519VrfDerivePublicKey(String privateKey);

    public static native SdkResult curve25519VrfProofToHash(String proof);

    public static native SdkResult curve25519VrfIsValidPublicKey(String publicKey);
}
```

```java
package com.webank.fisco.bcos.sdk;
import com.webank.wedpr.common.WedprException;
import com.webank.wedpr.common.WedprResult;

public class SdkResult extends WedprResult {
    public String publicKey;
    public String privateKey;
    public String hash;
    public boolean booleanResult;
    public String vrfProof;
}
```

```java
package com.webank.wedpr.common;

/** Base result class used by WeDPR Java SDK. */
public class WedprResult {
  public String wedprErrorMessage;

  /** Checks whether any error occurred. */
  public boolean hasError() {
    return wedprErrorMessage != null;
  }
}
```