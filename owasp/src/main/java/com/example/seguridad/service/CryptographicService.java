package com.example.seguridad.service;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.bcrypt.BCrypt;
import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

@Service
@Slf4j
public class CryptographicService {

    @Value("${crypto.secret.key:defaultSecretKeyForDevelopmentOnly}")
    private String secretKey;

    private static final int SALT_LENGTH = 16;
    private static final int ITERATION_COUNT = 65536;
    private static final int KEY_LENGTH = 256;
    private static final int GCM_IV_LENGTH = 12;
    private static final int GCM_TAG_LENGTH = 16;
    private static final int CBC_IV_LENGTH = 16;

    /**
     * Hash de contraseña usando BCrypt (buena práctica)
     */
    public String hashWithBCrypt(String password) {
        return BCrypt.hashpw(password, BCrypt.gensalt(12));
    }

    /**
     * Verificación de contraseña con BCrypt (buena práctica)
     */
    public boolean verifyBCryptPassword(String password, String hashedPassword) {
        return BCrypt.checkpw(password, hashedPassword);
    }

    /**
     * Hash de contraseña usando PBKDF2 con salt aleatorio (buena práctica)
     */
    public String hashWithPBKDF2(String password) throws NoSuchAlgorithmException, InvalidKeySpecException {
        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[SALT_LENGTH];
        random.nextBytes(salt);

        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, ITERATION_COUNT, KEY_LENGTH);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        byte[] hash = factory.generateSecret(spec).getEncoded();

        // Combinamos salt y hash para almacenarlos juntos
        byte[] combined = new byte[salt.length + hash.length];
        System.arraycopy(salt, 0, combined, 0, salt.length);
        System.arraycopy(hash, 0, combined, salt.length, hash.length);

        return Base64.getEncoder().encodeToString(combined);
    }

    /**
     * Cifrado usando AES en modo GCM (buena práctica)
     * GCM proporciona autenticación además de confidencialidad
     */
    public Map<String, String> encryptWithAESGCM(String plainText) throws Exception {
        // Generar clave segura
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(KEY_LENGTH);
        SecretKey secretKey = keyGenerator.generateKey();

        // Generar IV aleatorio
        byte[] iv = new byte[GCM_IV_LENGTH];
        new SecureRandom().nextBytes(iv);
        GCMParameterSpec parameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, iv);

        // Cifrar
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, parameterSpec);
        byte[] cipherText = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));

        // Combinar IV y texto cifrado
        ByteBuffer byteBuffer = ByteBuffer.allocate(iv.length + cipherText.length);
        byteBuffer.put(iv);
        byteBuffer.put(cipherText);
        byte[] cipherMessage = byteBuffer.array();

        Map<String, String> result = new HashMap<>();
        result.put("originalText", plainText);
        result.put("encryptedText", Base64.getEncoder().encodeToString(cipherMessage));
        result.put("key", Base64.getEncoder().encodeToString(secretKey.getEncoded()));
        result.put("method", "AES/GCM con IV aleatorio (SEGURO)");

        return result;
    }

    /**
     * Cifrado usando AES en modo CBC con IV aleatorio (buena práctica)
     */
    public Map<String, String> encryptWithAESCBC(String plainText) throws Exception {
        // Derivar clave a partir de la clave secreta
        byte[] salt = new byte[SALT_LENGTH];
        new SecureRandom().nextBytes(salt);

        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        KeySpec spec = new PBEKeySpec(secretKey.toCharArray(), salt, ITERATION_COUNT, KEY_LENGTH);
        SecretKey tmp = factory.generateSecret(spec);
        SecretKeySpec secretKeySpec = new SecretKeySpec(tmp.getEncoded(), "AES");

        // Generar IV aleatorio
        byte[] iv = new byte[CBC_IV_LENGTH];
        new SecureRandom().nextBytes(iv);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);

        // Cifrar
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);
        byte[] cipherText = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));

        // Combinar salt, IV y texto cifrado
        ByteBuffer byteBuffer = ByteBuffer.allocate(salt.length + iv.length + cipherText.length);
        byteBuffer.put(salt);
        byteBuffer.put(iv);
        byteBuffer.put(cipherText);
        byte[] cipherMessage = byteBuffer.array();

        Map<String, String> result = new HashMap<>();
        result.put("originalText", plainText);
        result.put("encryptedText", Base64.getEncoder().encodeToString(cipherMessage));
        result.put("method", "AES/CBC con IV aleatorio y salt (SEGURO)");

        return result;
    }
}