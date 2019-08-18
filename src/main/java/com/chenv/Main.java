package com.chenv;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;

import static com.chenv.OpenSSLRSAKeyUtils.readPKCS1PrivateKey;
import static com.chenv.OpenSSLRSAKeyUtils.readPKCS1PublicKey;
import static com.chenv.RSAUtils.decrypt;
import static com.chenv.RSAUtils.encrypt;

public class Main {
    public static void main(String[] args) {
        // 1. 读取pkcs1格式公钥
        String rsaPublicKey = "-----BEGIN RSA PUBLIC KEY-----\n" +
                "MIGHAoGBAKGGN8ZUTobeVSEcqN6wy+T1PfR45rBjM7Cyy1WC+dlYRwWrp/OwRBK0\n" +
                "uFtG71bOkRkQwbHAit4S5djQeve38tXppF6JdOorwWM417pCut/4NB4qbYiZFZTG\n" +
                "CKkMkHXd3kLq85n+AvbilTMQYSBvJeVlaUphjBoE+tz8QLu19FUTAgED\n" +
                "-----END RSA PUBLIC KEY-----";

        PublicKey publicKey = null;
        try {
            publicKey = readPKCS1PublicKey(rsaPublicKey);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        }
        System.out.println("public key(PKCS#8): ");
        System.out.println(Base64.getEncoder().encodeToString(publicKey.getEncoded()));

        // 2.读取pkcs1格式私钥
        String rsaPrivateKey = "-----BEGIN RSA PRIVATE KEY-----\n" +
                "MIICWwIBAAKBgQChhjfGVE6G3lUhHKjesMvk9T30eOawYzOwsstVgvnZWEcFq6fz\n" +
                "sEQStLhbRu9WzpEZEMGxwIreEuXY0Hr3t/LV6aReiXTqK8FjONe6Qrrf+DQeKm2I\n" +
                "mRWUxgipDJB13d5C6vOZ/gL24pUzEGEgbyXlZWlKYYwaBPrc/EC7tfRVEwIBAwKB\n" +
                "gGuuz9mNia8+42tocJR13UNOKU2l7yBCInXMh45XUTuQL1kdGqJ1grcjJZIvSjnf\n" +
                "C2YLK8vVselh7pCK/KUlTI2MVV8BFGrCWxB6wkmpUUBCFM3jhVctCQwgCqYli5bw\n" +
                "5IsRpP/hAFYPPQMTm6oYZhwc7ezXxsl3A3ydMlYpxFf7AkEA1Rrv1CYD45dnJxuP\n" +
                "I5q85mAoYhXTEKnBtmo8RHLv/o+i40+aL9BX1FvAbPuxCZlNf/62s7jpZE0va8VF\n" +
                "XvQt1QJBAMIJYDOwRiShY1mYvKEmQq60wPMPssTeQN+Oc4/MI3X3z20sf/yyHfdd\n" +
                "7gX78EDzbboFsGopAm4ocqSv9RhZo0cCQQCOEfU4GVftD5oaEl9tEdNEQBrsDoy1\n" +
                "xoEkRtLYTJ//CmyXimbKiuU4PSrzUnYGZjOqqc8ie0ZC3h+dLi4/TXPjAkEAgVuV\n" +
                "d8rZbcDs5mXTFhmByc3V91/Mgz7V6l73tTLCTqU083L//cwT+j6erqf1gKJJJq51\n" +
                "nBtW9Br3GHVOEDvCLwJAYNNG0o7HTF4bubgAtQF4PaheIa5YiYF9xTVRFKsQ9vxN\n" +
                "b/UUJEGeAANDRc29GmN8mbHHfW6YFPI7E1ntuTHarA==\n" +
                "-----END RSA PRIVATE KEY-----";
        PrivateKey privateKey = null;
        try {
            privateKey = readPKCS1PrivateKey(rsaPrivateKey);
        } catch (GeneralSecurityException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
        System.out.println("private key(PKCS#8):");
        System.out.println(Base64.getEncoder().encodeToString(privateKey.getEncoded()));

        String str = "abc";

        try {
            System.out.println("str: \n" + str);
            String encryptStr = encrypt(str, publicKey);
            System.out.println("encrypt: \n" + encryptStr);
            String decryptStr = decrypt(encryptStr, privateKey);
            System.out.println("decrypt: \n" + decryptStr);
        } catch (Exception e) {
            e.printStackTrace();
        }

    }
}
