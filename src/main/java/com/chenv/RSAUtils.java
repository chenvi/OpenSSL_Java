package com.chenv;

import javax.crypto.Cipher;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class RSAUtils {

    public static String encrypt(String str, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        String encodeStr = Base64.getEncoder().encodeToString(cipher.doFinal(str.getBytes(StandardCharsets.UTF_8)));
        return encodeStr;
    }

    public static String decrypt(String str, PrivateKey privateKey) throws Exception {
        byte[] strByte = Base64.getDecoder().decode(str.getBytes(StandardCharsets.UTF_8));
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        String decodeStr = new String(cipher.doFinal(strByte));
        return decodeStr;
    }

    public static String encrypt(String str, String publicKey) throws Exception {
        // public key str decode by base64
        byte[] decoded = Base64.getDecoder().decode(publicKey.getBytes(StandardCharsets.UTF_8));
        RSAPublicKey pubKey = (RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(decoded));
        // RSA encode
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, pubKey);
        String encodeStr = Base64.getEncoder().encodeToString(cipher.doFinal(str.getBytes(StandardCharsets.UTF_8)));
        return encodeStr;
    }

    public static String decrypt(String str, String privateKey) throws Exception {
        // to decrypt str
        byte[] strByte = Base64.getDecoder().decode(str.getBytes(StandardCharsets.UTF_8));
        // private key str decode by base64
        byte[] decoded = Base64.getDecoder().decode(privateKey);
        RSAPrivateKey priKey = (RSAPrivateKey) KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(decoded));
        // RSA decode
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, priKey);
        String decodeStr = new String(cipher.doFinal(strByte));
        return decodeStr;
    }
}
