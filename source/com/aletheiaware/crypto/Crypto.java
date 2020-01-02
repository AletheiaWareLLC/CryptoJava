/*
 * Copyright 2020 Aletheia Ware LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.aletheiaware.crypto;

import com.aletheiaware.crypto.CryptoProto.EncryptionAlgorithm;
import com.aletheiaware.crypto.CryptoProto.KeyShare;
import com.aletheiaware.crypto.CryptoProto.SignatureAlgorithm;
import com.aletheiaware.common.utils.CommonUtils;

import com.google.protobuf.MessageLite;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.Socket;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.KeySpec;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.text.DateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Scanner;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.EncryptedPrivateKeyInfo;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import javax.crypto.spec.PSource.PSpecified;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.HttpsURLConnection;

public final class Crypto {

    public static final int AES_KEY_SIZE_BITS = 128;
    public static final int AES_KEY_SIZE_BYTES = AES_KEY_SIZE_BITS / 8;
    public static final int AES_IV_SIZE_BITS = 96;
    public static final int AES_IV_SIZE_BYTES = AES_IV_SIZE_BITS / 8;
    public static final int GCM_TAG_SIZE_BITS = 128;
    public static final int GCM_TAG_SIZE_BYTES = GCM_TAG_SIZE_BITS / 8;
    public static final int HASH_SIZE = 512;
    public static final int PBE_ITERATIONS = 10000;
    public static final int RSA_KEY_SIZE_BITS = 4096;

    public static final String AES = "AES";
    public static final String AES_CIPHER = "AES/GCM/NoPadding";
    public static final String HASH_DIGEST = "SHA-512";
    public static final String PBE_CIPHER = "PBKDF2WithHmacSHA1";
    public static final String RSA = "RSA";
    public static final String RSA_CIPHER = "RSA/ECB/OAEPPadding";
    public static final String SIGNATURE_ALGORITHM = "SHA512withRSA";
    public static final String PRIVATE_KEY_EXT = ".java.private";
    public static final String PUBLIC_KEY_EXT = ".java.public";

    private Crypto() {}

    public static byte[] getHash(byte[] data) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance(HASH_DIGEST);
        digest.reset();
        return digest.digest(data);
    }

    public static byte[] getProtobufHash(MessageLite message) throws NoSuchAlgorithmException {
        byte[] data = message.toByteArray();
        return getHash(data);
    }

    /*
     * Create a random AES secret key.
     */
    public static byte[] generateSecretKey() {
        return generateSecretKey(AES_KEY_SIZE_BYTES);
    }

    /*
     * Create a random AES secret key.
     */
    public static byte[] generateSecretKey(int size) {
        byte[] k = new byte[size];
        SecureRandom r = new SecureRandom();
        r.nextBytes(k);
        return k;
    }

    /**
     * Encrypts the data with the secret key.
     *
     * <p>Generates an initialization vector and prepends to the encrypted data result.</p>
     */
    public static byte[] encryptAES(byte[] key, byte[] data) throws BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException {
        SecureRandom r = new SecureRandom();

        // Create initialization vector
        byte[] iv = new byte[AES_IV_SIZE_BYTES];
        r.nextBytes(iv);

        GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_SIZE_BITS, iv);

        // Create AES Cipher
        Cipher cipher = Cipher.getInstance(AES_CIPHER);
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, AES), gcmSpec);

        // Encrypt the data with the key
        byte[] encryptedData = cipher.doFinal(data);

        // Create result array
        byte[] result = new byte[AES_IV_SIZE_BYTES + encryptedData.length];
        // Copy iv to result
        System.arraycopy(iv, 0, result, 0, AES_IV_SIZE_BYTES);
        // Copy encrypted data to result
        System.arraycopy(encryptedData, 0, result, AES_IV_SIZE_BYTES, encryptedData.length);
        return result;
    }

    /**
     * Encrypts the data with the password.
     *
     * <p>Generates a salt and an initialization vector and prepends them to the encrypted data result.</p>
     */
    public static byte[] encryptAES(char[] password, byte[] data) throws BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException, InvalidKeyException, InvalidKeySpecException, NoSuchAlgorithmException, NoSuchPaddingException {
        SecureRandom r = new SecureRandom();

        // Create salt
        byte[] salt = new byte[AES_KEY_SIZE_BYTES];
        r.nextBytes(salt);

        // Create initialization vector
        byte[] iv = new byte[AES_IV_SIZE_BYTES];
        r.nextBytes(iv);

        GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_SIZE_BITS, iv);

        // Create PBE Key
        SecretKeyFactory factory = SecretKeyFactory.getInstance(PBE_CIPHER);
        PBEKeySpec pbeSpec = new PBEKeySpec(password, salt, PBE_ITERATIONS, AES_KEY_SIZE_BITS);
        SecretKeySpec pbeKey = new SecretKeySpec(factory.generateSecret(pbeSpec).getEncoded(), AES);

        // Create AES Cipher
        Cipher cipher = Cipher.getInstance(AES_CIPHER);
        cipher.init(Cipher.ENCRYPT_MODE, pbeKey, gcmSpec);

        // Encrypt the data with the PBE key
        byte[] encryptedData = cipher.doFinal(data);

        // Create result array
        byte[] result = new byte[AES_KEY_SIZE_BYTES + AES_IV_SIZE_BYTES + encryptedData.length];
        // Copy salt to result
        System.arraycopy(salt, 0, result, 0, AES_KEY_SIZE_BYTES);
        // Copy iv to result
        System.arraycopy(iv, 0, result, AES_KEY_SIZE_BYTES, AES_IV_SIZE_BYTES);
        // Copy encrypted data to result
        System.arraycopy(encryptedData, 0, result, AES_KEY_SIZE_BYTES + AES_IV_SIZE_BYTES, encryptedData.length);
        return result;
    }

    /**
     * Decrypts the data with the secret key.
     *
     * <p>Uses an initialization vector at the start of data.</p>
     */
    public static byte[] decryptAES(byte[] key, byte[] data) throws BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException {
        // Decrypt with the secret key
        SecretKeySpec secretKey = new SecretKeySpec(key, AES);
        byte[] iv = new byte[AES_IV_SIZE_BYTES];
        // Copy iv from data
        System.arraycopy(data, 0, iv, 0, AES_IV_SIZE_BYTES);
        GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_SIZE_BITS, iv);
        int encryptedLength = data.length - AES_IV_SIZE_BYTES;
        byte[] encryptedData = new byte[encryptedLength];
        System.arraycopy(data, AES_IV_SIZE_BYTES, encryptedData, 0, encryptedLength);
        Cipher cipher = Cipher.getInstance(AES_CIPHER);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, gcmSpec);
        byte[] decryptedData = cipher.doFinal(encryptedData);
        return decryptedData;
    }

    /**
     * Decrypts the data with the password.
     *
     * <p>Uses a salt and an initialization vector at the start of data.</p>
     */
    public static byte[] decryptAES(char[] password, byte[] data) throws BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException, InvalidKeyException, InvalidKeySpecException, NoSuchAlgorithmException, NoSuchPaddingException {
        byte[] salt = new byte[AES_KEY_SIZE_BYTES];
        byte[] iv = new byte[AES_IV_SIZE_BYTES];
        // Copy salt from data
        System.arraycopy(data, 0, salt, 0, AES_KEY_SIZE_BYTES);
        // Copy iv from data
        System.arraycopy(data, AES_KEY_SIZE_BYTES, iv, 0, AES_IV_SIZE_BYTES);
        GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_SIZE_BITS, iv);
        // Copy encrypted payload from data
        int encryptedLength = data.length - AES_KEY_SIZE_BYTES - AES_IV_SIZE_BYTES;
        byte[] encryptedData = new byte[encryptedLength];
        System.arraycopy(data, AES_KEY_SIZE_BYTES + AES_IV_SIZE_BYTES, encryptedData, 0, encryptedLength);

        // Create PBE Key
        SecretKeyFactory factory = SecretKeyFactory.getInstance(PBE_CIPHER);
        PBEKeySpec pbeSpec = new PBEKeySpec(password, salt, PBE_ITERATIONS, AES_KEY_SIZE_BITS);
        SecretKeySpec pbeKey = new SecretKeySpec(factory.generateSecret(pbeSpec).getEncoded(), AES);

        // Create AES Cipher
        Cipher cipher = Cipher.getInstance(AES_CIPHER);
        cipher.init(Cipher.DECRYPT_MODE, pbeKey, gcmSpec);

        // Decrypt the data with the PBE key
        byte[] decryptedData = cipher.doFinal(encryptedData);
        return decryptedData;
    }

    /*
     * Create RSA key pair from given seed.
     *
    public static KeyPair generateKeyPair(long seed) throws BadPaddingException, IOException, IllegalBlockSizeException, InvalidAlgorithmParameterException, InvalidKeyException, InvalidKeySpecException, InvalidParameterSpecException, NoSuchAlgorithmException, NoSuchPaddingException {
        System.out.println("Generating " + RSA_KEY_SIZE_BITS + "bit " + RSA + " key pair from seed");
        KeyPairGenerator generator = KeyPairGenerator.getInstance(RSA);
        generator.initialize(RSA_KEY_SIZE_BITS, seed);
        return generator.genKeyPair();
    }
    /* End generateKeyPair */

    /*
     * Create a random RSA key pair.
     */
    public static KeyPair createRSAKeyPair() throws BadPaddingException, IOException, IllegalBlockSizeException, InvalidAlgorithmParameterException, InvalidKeyException, InvalidKeySpecException, InvalidParameterSpecException, NoSuchAlgorithmException, NoSuchPaddingException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance(RSA);
        generator.initialize(RSA_KEY_SIZE_BITS);
        return generator.genKeyPair();
    }

    /*
     * Create a random RSA key pair.
     */
    public static KeyPair createRSAKeyPair(File directory, String alias, char[] password) throws BadPaddingException, IOException, IllegalBlockSizeException, InvalidAlgorithmParameterException, InvalidKeyException, InvalidKeySpecException, InvalidParameterSpecException, NoSuchAlgorithmException, NoSuchPaddingException {
        System.out.println("Creating " + RSA_KEY_SIZE_BITS + "bit " + RSA + " key pair: " + alias);
        KeyPair pair = createRSAKeyPair();
        writeRSAKeyPair(directory, alias, password, pair);
        return pair;
    }

    /*
     * Create an RSA key pair from the given private key format and bytes.
     */
    public static KeyPair importRSAKeyPair(File directory, String accessCode, KeyShare ks) throws BadPaddingException, IOException, IllegalBlockSizeException, InvalidAlgorithmParameterException, InvalidKeyException, InvalidKeySpecException, InvalidParameterSpecException, NoSuchAlgorithmException, NoSuchPaddingException {
        byte[] key = CommonUtils.decodeBase64URL(accessCode.getBytes("utf-8"));
        KeySpec publicSpec = null;
        byte[] pub = ks.getPublicKey().toByteArray();
        switch (ks.getPublicFormat()) {
            case PKIX:
            case X509:
                publicSpec = new X509EncodedKeySpec(pub);
                break;
            case UNKNOWN_PUBLIC_KEY_FORMAT:
            default:
                throw new IllegalArgumentException("Unknown public key format: " + ks.getPublicFormat());
        }
        KeySpec privateSpec = null;
        byte[] priv = decryptAES(key, ks.getPrivateKey().toByteArray());
        switch (ks.getPrivateFormat()) {
            case PKCS8:
                privateSpec = new PKCS8EncodedKeySpec(priv);
                break;
            case UNKNOWN_PRIVATE_KEY_FORMAT:
            default:
                throw new IllegalArgumentException("Unknown private key format: " + ks.getPrivateFormat());
        }
        PrivateKey privateKey = KeyFactory.getInstance(RSA).generatePrivate(privateSpec);
        PublicKey publicKey = KeyFactory.getInstance(RSA).generatePublic(publicSpec);
        KeyPair pair = new KeyPair(publicKey, privateKey);
        char[] password = new String(decryptAES(key, ks.getPassword().toByteArray())).toCharArray();
        writeRSAKeyPair(directory, ks.getName(), password, pair);
        return pair;
    }

    /*
     * Write an RSA key pair to files.
     */
    public static void writeRSAKeyPair(File directory, String alias, char[] password, KeyPair pair) throws BadPaddingException, IOException, IllegalBlockSizeException, InvalidAlgorithmParameterException, InvalidKeyException, InvalidKeySpecException, InvalidParameterSpecException, NoSuchAlgorithmException, NoSuchPaddingException {
        byte[] privateKeyBytes = pair.getPrivate().getEncoded();
        byte[] publicKeyBytes = pair.getPublic().getEncoded();
        if (alias == null || alias.isEmpty()) {
            alias = new String(CommonUtils.encodeBase64URL(getHash(publicKeyBytes)));
        }
        File privFile = new File(directory, alias + PRIVATE_KEY_EXT);
        File pubFile = new File(directory, alias + PUBLIC_KEY_EXT);
        CommonUtils.writeFile(privFile, encryptAES(password, privateKeyBytes));
        CommonUtils.writeFile(pubFile, publicKeyBytes);
    }

    /**
     * Exports the given alias and keys to the server for importing to another device.
     */
    public static void exportKeyPair(String host, File directory, String alias, char[] password, KeyPair keys, byte[] accessCode) throws BadPaddingException, IOException, IllegalBlockSizeException, InvalidAlgorithmParameterException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException {
        String publicKeyFormat = keys.getPublic().getFormat().replaceAll("\\.", "");// Remove dot from X.509
        String privateKeyFormat = keys.getPrivate().getFormat().replaceAll("#", "");// Remove hash from PKCS#8
        byte[] publicKeyBytes = keys.getPublic().getEncoded();
        byte[] privateKeyBytes = keys.getPrivate().getEncoded();
        byte[] encryptedPrivateKeyBytes = encryptAES(accessCode, privateKeyBytes);
        byte[] encryptedPassword = encryptAES(accessCode, new String(password).getBytes("utf-8"));
        String params = "alias=" + URLEncoder.encode(alias, "utf-8")
                + "&publicKey=" + new String(CommonUtils.encodeBase64URL(publicKeyBytes), "utf-8")
                + "&publicKeyFormat=" + URLEncoder.encode(publicKeyFormat, "utf-8")
                + "&privateKey=" + new String(CommonUtils.encodeBase64URL(encryptedPrivateKeyBytes), "utf-8")
                + "&privateKeyFormat=" + URLEncoder.encode(privateKeyFormat, "utf-8")
                + "&password=" + new String(CommonUtils.encodeBase64URL(encryptedPassword), "utf-8");
        System.out.println("Params:" + params);
        byte[] data = params.getBytes(StandardCharsets.UTF_8);

        URL url = new URL(host + "/keys");
        HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();
        conn.setDoOutput(true);
        conn.setInstanceFollowRedirects(false);
        conn.setRequestMethod("POST");
        conn.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
        conn.setRequestProperty("charset", "utf-8");
        conn.setRequestProperty("Content-Length", Integer.toString(data.length));
        conn.setUseCaches(false);
        try (OutputStream o = conn.getOutputStream()) {
            o.write(data);
            o.flush();
        }

        int response = conn.getResponseCode();
        System.out.println("Response: " + response);
        Scanner in = new Scanner(conn.getInputStream());
        while (in.hasNextLine()) {
            System.out.println(in.nextLine());
        }
    }

    /**
     * Get the key share for the given alias from the server.
     */
    public static KeyShare getKeyShare(String host, String alias) throws IOException {
        URL url = new URL(host + "/keys?alias=" + URLEncoder.encode(alias, "utf-8"));
        HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();
        conn.setInstanceFollowRedirects(false);
        conn.setRequestMethod("GET");
        conn.setUseCaches(false);

        int response = conn.getResponseCode();
        System.out.println("Response: " + response);
        KeyShare ks = KeyShare.newBuilder().mergeFrom(conn.getInputStream()).build();
        System.out.println("KeyShare: " + ks);
        return ks;
    }

    public static boolean deleteRSAKeyPair(File directory, String alias) {
        return new File(directory, alias + PRIVATE_KEY_EXT).delete()
                && new File(directory, alias + PUBLIC_KEY_EXT).delete();
    }

    public static List<String> listRSAKeyPairs(File directory) {
        List<String> aliases = new ArrayList<>();
        for (String f : directory.list()) {
            if (f.endsWith(PRIVATE_KEY_EXT)) {
                aliases.add(f.substring(0, f.length() - PRIVATE_KEY_EXT.length()));
            }
        }
        return aliases;
    }

    public static KeyPair getRSAKeyPair(File directory, String alias, char[] password) throws BadPaddingException, IOException, IllegalBlockSizeException, InvalidAlgorithmParameterException, InvalidKeyException, InvalidKeySpecException, InvalidParameterSpecException, NoSuchAlgorithmException, NoSuchPaddingException {
        File privFile = new File(directory, alias + PRIVATE_KEY_EXT);
        File pubFile = new File(directory, alias + PUBLIC_KEY_EXT);
        byte[] privBytes = decryptAES(password, CommonUtils.readFile(privFile));
        byte[] pubBytes = CommonUtils.readFile(pubFile);
        PrivateKey privKey = KeyFactory.getInstance(RSA).generatePrivate(new PKCS8EncodedKeySpec(privBytes));
        PublicKey pubKey = KeyFactory.getInstance(RSA).generatePublic(new X509EncodedKeySpec(pubBytes));
        return new KeyPair(pubKey, privKey);
    }

    public static byte[] encryptRSA(PublicKey publicKey, byte[] data) throws BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException {
        Cipher cipher = Cipher.getInstance(RSA_CIPHER);
        OAEPParameterSpec params = new OAEPParameterSpec(HASH_DIGEST, "MGF1", new MGF1ParameterSpec(HASH_DIGEST), PSpecified.DEFAULT);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey, params);
        return cipher.doFinal(data);
    }

    public static byte[] decryptRSA(PrivateKey privateKey, byte[] data) throws BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException {
        Cipher cipher = Cipher.getInstance(RSA_CIPHER);
        OAEPParameterSpec params = new OAEPParameterSpec(HASH_DIGEST, "MGF1", new MGF1ParameterSpec(HASH_DIGEST), PSpecified.DEFAULT);
        cipher.init(Cipher.DECRYPT_MODE, privateKey, params);
        return cipher.doFinal(data);
    }

    public static byte[] sign(PrivateKey key, byte[] data) throws InvalidKeyException, NoSuchAlgorithmException, SignatureException {
        Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
        signature.initSign(key);
        signature.update(data);
        return signature.sign();
    }

    public static boolean verify(PublicKey key, byte[] data, byte[] sig) throws InvalidKeyException, NoSuchAlgorithmException, SignatureException {
        Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
        signature.initVerify(key);
        signature.update(data);
        return signature.verify(sig);
    }
}
