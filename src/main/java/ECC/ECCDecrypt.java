package ECC;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.*;

public class ECCDecrypt {
    private final PrivateKey privateKey; byte[] ECCEncryptedMessage;
    public ECCDecrypt(PrivateKey privateKey, byte[] ECCEncryptedMessage) {
        this.privateKey =privateKey;
        this.ECCEncryptedMessage = ECCEncryptedMessage;
    }

    public String ECCDecrypt() throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchProviderException {
        Cipher decryptCipher = Cipher.getInstance("ECIES", "BC");
        decryptCipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decryptedMessageBytes = decryptCipher.doFinal(ECCEncryptedMessage);
        return new String(decryptedMessageBytes);
    }
}
