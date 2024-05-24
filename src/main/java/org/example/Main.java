package org.example;

import ECC.ECCDecrypt;
import ECC.ECCEncrypt;
import ECCKey.ECCKeyGenerator;
import ECCKey.KeyToFiles;
import ECCKey.extractKeysFromFile;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;

public class Main {
    public static void main(String[] args) throws IOException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeySpecException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, NoSuchProviderException {
        System.out.println("Secret message to be encrypted : " + args[0]);
        String message = args[0];
        KeyPair pair = getKeyPair();
        saveKeysToFiles(pair);
        ExtractKeys key = getExtractKeys();
        EncryptedMessage ECCEncryptionResult = getEncryptedMessage(key, message);
        System.out.println("\n Encrypted Message: \n" + ECCEncryptionResult.encodedMessage());
        String decryptedMessage = getDecryptedMessage(key, ECCEncryptionResult); // Step 5: Decrypt the encrypted text using the public key in the file
        System.out.println("\n Decrypted Message: \n" + decryptedMessage);
    }

    private static ExtractKeys getExtractKeys() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        PublicKey publicKey = (PublicKey) extractKeysFromFile.getKey("ECC_publicKey.pem", "public");
        PrivateKey privateKey = (PrivateKey) extractKeysFromFile.getKey("ECC_privateKey.pem", "private");
        return new ExtractKeys(publicKey, privateKey);
    }

    private record ExtractKeys(PublicKey publicKey, PrivateKey privateKey) {
    }

    private static KeyPair getKeyPair() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException {
        ECCKeyGenerator ecckey = new ECCKeyGenerator();
        return ecckey.getKeyGenerator();
    }

    private static void saveKeysToFiles(KeyPair pair) throws IOException {
        KeyToFiles keyfile = new KeyToFiles();
        keyfile.savePemFile("ECC_publicKey.pem", "PUBLIC KEY", pair.getPublic().getEncoded());
        keyfile.savePemFile("ECC_privateKey.pem", "PRIVATE KEY", pair.getPrivate().getEncoded());
    }

    private static EncryptedMessage getEncryptedMessage(ExtractKeys key, String message) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidKeySpecException, NoSuchProviderException {
        System.out.println("\n Public key used by sender for encrypting message: \n" + key.publicKey());
        ECCEncrypt eccEncrypt  = new ECCEncrypt(key.publicKey(), message);
        byte[] encryptedMessage = eccEncrypt.getECCEncryptedMessage();
        String encodedMessage = Base64.getEncoder().encodeToString(encryptedMessage);
        return new EncryptedMessage(encryptedMessage, encodedMessage);
    }

    private record EncryptedMessage(byte[] encryptedMessage, String encodedMessage) {
    }

    private static String getDecryptedMessage(ExtractKeys key, EncryptedMessage ECCEncryptionResult) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchProviderException {
        System.out.println("\n Private key used by recipient for decrypting message: \n" + key.privateKey());
        ECCDecrypt ecc = new ECCDecrypt(key.privateKey(), ECCEncryptionResult.encryptedMessage());
        return ecc.ECCDecrypt();
    }

}