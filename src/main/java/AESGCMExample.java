import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.security.SecureRandom;
import java.util.Base64;

public class AESGCMExample {
    private static final int IV_SIZE = 12; // 96 bits recommandés
    private static final int TAG_SIZE = 128; // bits

    public static void main(String[] args) throws Exception {
        String message = "Données sensibles";

        // Génération clé AES
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        SecretKey key = keyGen.generateKey();

        // Génération IV aléatoire
        byte[] iv = new byte[IV_SIZE];
        new SecureRandom().nextBytes(iv);

        // Chiffrement
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(TAG_SIZE, iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, spec);
        byte[] encrypted = cipher.doFinal(message.getBytes());

        System.out.println("IV (Base64): " + Base64.getEncoder().encodeToString(iv));
        System.out.println("Chiffré (Base64): " + Base64.getEncoder().encodeToString(encrypted));

        // Déchiffrement
        cipher.init(Cipher.DECRYPT_MODE, key, spec);
        byte[] decrypted = cipher.doFinal(encrypted);

        System.out.println("Déchiffré: " + new String(decrypted));
    }
}
