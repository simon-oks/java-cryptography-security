import org.bouncycastle.jce.provider.BouncyCastleProvider;
import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.Mac;
import javax.crypto.Cipher;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;
import java.util.Base64;

public class ECDH_HKDF_AES {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public static void main(String[] args) throws Exception {
        // 1. Générez les paires de clés (Hôpital et Assureur)
        KeyPair hospitalKeys = generateKeyPair();
        KeyPair assureurKeys = generateKeyPair();

        // 2. Chaque partie calcule le secret partagé
        byte[] sharedSecretHopital = computeSharedSecret(hospitalKeys.getPrivate(), assureurKeys.getPublic());
        byte[] sharedSecretAssureur = computeSharedSecret(assureurKeys.getPrivate(), hospitalKeys.getPublic());

        // Vérification
        System.out.println("Secret égal ? " + Arrays.equals(sharedSecretHopital, sharedSecretAssureur));

        // 3. Dérive la clé AES avec HKDF
        byte[] salt = "static-salt-value".getBytes(); // Tu peux le randomiser
        SecretKey aesKeyHopital = hkdf(sharedSecretHopital, salt);
        SecretKey aesKeyAssureur = hkdf(sharedSecretAssureur, salt);

        // 4. Hôpital chiffre un message
        String message = "Données confidentielles";
        byte[] encrypted = encrypt(message, aesKeyHopital);
        System.out.println("Chiffré : " + Base64.getEncoder().encodeToString(encrypted));

        // 5. Assureur déchiffre
        String decrypted = decrypt(encrypted, aesKeyAssureur);
        System.out.println("Déchiffré : " + decrypted);
    }

    public static KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC", "BC");
        keyPairGenerator.initialize(new ECGenParameterSpec("secp256r1")); // P-256
        return keyPairGenerator.generateKeyPair();
    }

    public static byte[] computeSharedSecret(PrivateKey privKey, PublicKey pubKey) throws Exception {
        KeyAgreement ka = KeyAgreement.getInstance("ECDH", "BC");
        ka.init(privKey);
        ka.doPhase(pubKey, true);
        return ka.generateSecret();
    }

    public static SecretKey hkdf(byte[] sharedSecret, byte[] salt) throws Exception {
        Mac hmac = Mac.getInstance("HmacSHA256");
        SecretKeySpec saltKey = new SecretKeySpec(salt, "HmacSHA256");
        hmac.init(saltKey);
        byte[] keyBytes = hmac.doFinal(sharedSecret);
        return new SecretKeySpec(keyBytes, 0, 32, "AES"); // AES-256
    }

    public static byte[] encrypt(String plainText, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(plainText.getBytes());
    }

    public static String decrypt(byte[] cipherText, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, key);
        return new String(cipher.doFinal(cipherText));
    }
}
