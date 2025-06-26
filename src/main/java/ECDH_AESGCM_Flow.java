import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

public class ECDH_AESGCM_Flow {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    private static final int AES_KEY_SIZE = 32; // 256 bits
    private static final int IV_SIZE = 12;      // 96 bits recommandé pour GCM
    private static final int TAG_SIZE = 128;    // en bits

    public static void main(String[] args) throws Exception {
        // 1. Générer les paires de clés ECDH
        KeyPair senderKeys = generateKeyPair();     // Hôpital
        KeyPair receiverKeys = generateKeyPair();   // Assureur

        // 2. Calculer le shared secret (chaque côté)
        byte[] sharedSecretSender = computeSharedSecret(senderKeys.getPrivate(), receiverKeys.getPublic());
        byte[] sharedSecretReceiver = computeSharedSecret(receiverKeys.getPrivate(), senderKeys.getPublic());

        // 3. Générer un salt aléatoire
        byte[] salt = new byte[16];
        new SecureRandom().nextBytes(salt);

        // 4. Dériver une clé AES avec HKDF + salt
        SecretKey aesKeySender = hkdf(sharedSecretSender, salt);
        SecretKey aesKeyReceiver = hkdf(sharedSecretReceiver, salt);

        // 5. Générer un IV aléatoire pour AES-GCM
        byte[] iv = new byte[IV_SIZE];
        new SecureRandom().nextBytes(iv);

        // 6. Chiffrer le message
        String message = "Données médicales sensibles à fournir";
        byte[] ciphertext = encryptAESGCM(aesKeySender, iv, message.getBytes());

        // 7. Construire le JSON à envoyer
        Map<String, String> jsonMessage = new HashMap<>();
        jsonMessage.put("salt", Base64.getEncoder().encodeToString(salt));
        jsonMessage.put("iv", Base64.getEncoder().encodeToString(iv));
        jsonMessage.put("ciphertext", Base64.getEncoder().encodeToString(ciphertext));

        System.out.println("\n--- Message envoyé ---");
        jsonMessage.forEach((k, v) -> System.out.println(k + ": " + v));

        // 8. Réception et déchiffrement
        byte[] receivedSalt = Base64.getDecoder().decode(jsonMessage.get("salt"));
        byte[] receivedIv = Base64.getDecoder().decode(jsonMessage.get("iv"));
        byte[] receivedCiphertext = Base64.getDecoder().decode(jsonMessage.get("ciphertext"));

        SecretKey finalKey = hkdf(sharedSecretReceiver, receivedSalt);
        byte[] decrypted = decryptAESGCM(finalKey, receivedIv, receivedCiphertext);

        System.out.println("--- Message déchiffré ---");
                System.out.println(new String(decrypted));
    }

    public static KeyPair generateKeyPair() throws Exception {
        return ECDH_HKDF_AES.generateKeyPair();
    }

    public static byte[] computeSharedSecret(PrivateKey privKey, PublicKey pubKey) throws Exception {
        return ECDH_HKDF_AES.computeSharedSecret(privKey, pubKey);
    }

    public static SecretKey hkdf(byte[] secret, byte[] salt) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        SecretKeySpec saltKey = new SecretKeySpec(salt, "HmacSHA256");
        mac.init(saltKey);
        byte[] keyBytes = mac.doFinal(secret);
        return new SecretKeySpec(keyBytes, 0, AES_KEY_SIZE, "AES");
    }

    public static byte[] encryptAESGCM(SecretKey key, byte[] iv, byte[] plaintext) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec gcmSpec = new GCMParameterSpec(TAG_SIZE, iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, gcmSpec);
        return cipher.doFinal(plaintext);
    }

    public static byte[] decryptAESGCM(SecretKey key, byte[] iv, byte[] ciphertext) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec gcmSpec = new GCMParameterSpec(TAG_SIZE, iv);
        cipher.init(Cipher.DECRYPT_MODE, key, gcmSpec);
        return cipher.doFinal(ciphertext);
    }
}
