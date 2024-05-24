package ECCKey;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Base64;

public class KeyToFiles {
    public void savePemFile(String fileName, String header, byte[] keyBytes) throws IOException {
        Base64.Encoder encoder = Base64.getMimeEncoder(64, new byte[]{'\n'});
        String encodedKey = encoder.encodeToString(keyBytes);
        String pemKey = String.format("-----BEGIN %s-----\n%s\n-----END %s-----\n", header, encodedKey, header);
        Files.write(Paths.get(fileName), pemKey.getBytes());
    }
}
