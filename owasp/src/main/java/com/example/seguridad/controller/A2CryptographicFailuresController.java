package com.example.seguridad.controller;

import com.example.seguridad.model.UserCredential;
import com.example.seguridad.model.UserResponse;
import com.example.seguridad.service.CryptographicService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/crypto")
@RequiredArgsConstructor
@Slf4j
public class A2CryptographicFailuresController {

    private final CryptographicService cryptographicService;

    // Ejemplos de MALAS PRÁCTICAS

    /**
     * MALA PRÁCTICA 1: Uso de algoritmo de hash débil (MD5)
     * MD5 es considerado inseguro y vulnerable a colisiones
     */
    @PostMapping("/bad/hash-md5")
    public ResponseEntity<UserResponse> badHashPasswordMD5(@RequestBody UserCredential userCredential) {
        try {
            String password = userCredential.getPassword();

            // INSEGURO: Usando MD5 (algoritmo débil)
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] hashBytes = md.digest(password.getBytes(StandardCharsets.UTF_8));

            StringBuilder sb = new StringBuilder();
            for (byte b : hashBytes) {
                sb.append(String.format("%02x", b));
            }
            String hashedPassword = sb.toString();

            return ResponseEntity.ok(new UserResponse(userCredential.getUsername(), hashedPassword, "MD5 (INSEGURO)"));
        } catch (NoSuchAlgorithmException e) {
            log.error("Error al hash con MD5", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }

    /**
     * MALA PRÁCTICA 2: Uso de algoritmo de hash SHA-1
     * SHA-1 es también inseguro para uso criptográfico moderno
     */
    @PostMapping("/bad/hash-sha1")
    public ResponseEntity<UserResponse> badHashPasswordSHA1(@RequestBody UserCredential userCredential) {
        try {
            String password = userCredential.getPassword();

            // INSEGURO: Usando SHA-1 (algoritmo débil)
            MessageDigest md = MessageDigest.getInstance("SHA-1");
            byte[] hashBytes = md.digest(password.getBytes(StandardCharsets.UTF_8));

            StringBuilder sb = new StringBuilder();
            for (byte b : hashBytes) {
                sb.append(String.format("%02x", b));
            }
            String hashedPassword = sb.toString();

            return ResponseEntity.ok(new UserResponse(userCredential.getUsername(), hashedPassword, "SHA-1 (INSEGURO)"));
        } catch (NoSuchAlgorithmException e) {
            log.error("Error al hash con SHA-1", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }

    /**
     * MALA PRÁCTICA 3: Uso de clave hardcodeada y algoritmo débil
     * Hardcodear claves de cifrado en el código es una mala práctica
     */
    @PostMapping("/bad/encrypt-hardcoded")
    public ResponseEntity<Map<String, String>> badEncryptHardcoded(@RequestBody Map<String, String> payload) {
        try {
            String textToEncrypt = payload.get("text");

            // INSEGURO: Clave hardcodeada en el código
            String hardcodedKey = "ThisIsAHardcoded32BytesSecretKey!!";

            // INSEGURO: Usando DES (algoritmo débil)
            Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
            SecretKeySpec secretKey = new SecretKeySpec(hardcodedKey.substring(0, 8).getBytes(), "DES");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);

            byte[] encryptedBytes = cipher.doFinal(textToEncrypt.getBytes(StandardCharsets.UTF_8));
            String encryptedText = Base64.getEncoder().encodeToString(encryptedBytes);

            Map<String, String> response = new HashMap<>();
            response.put("originalText", textToEncrypt);
            response.put("encryptedText", encryptedText);
            response.put("method", "DES con clave hardcodeada (INSEGURO)");

            return ResponseEntity.ok(response);
        } catch (Exception e) {
            log.error("Error al encriptar con clave hardcodeada", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }

    /**
     * BUENA PRÁCTICA 1: Uso de BCrypt para hash de contraseñas
     * BCrypt incluye salt automáticamente y es resistente a ataques de fuerza bruta
     */
    @PostMapping("/good/hash-bcrypt")
    public ResponseEntity<UserResponse> goodHashBCrypt(@RequestBody UserCredential userCredential) {
        String password = userCredential.getPassword();

        // SEGURO: Usando BCrypt (algoritmo fuerte para passwords)
        String hashedPassword = cryptographicService.hashWithBCrypt(password);

        return ResponseEntity.ok(new UserResponse(userCredential.getUsername(), hashedPassword, "BCrypt (SEGURO)"));
    }

    /**
     * BUENA PRÁCTICA 2: Uso de PBKDF2 con iteraciones adecuadas
     * PBKDF2 es un algoritmo de derivación de claves que aplica una función pseudoaleatoria
     */
    @PostMapping("/good/hash-pbkdf2")
    public ResponseEntity<UserResponse> goodHashPBKDF2(@RequestBody UserCredential userCredential) {
        try {
            String password = userCredential.getPassword();

            // SEGURO: Usando PBKDF2 con salt aleatorio e iteraciones
            String hashedPassword = cryptographicService.hashWithPBKDF2(password);

            return ResponseEntity.ok(new UserResponse(userCredential.getUsername(), hashedPassword, "PBKDF2 (SEGURO)"));
        } catch (Exception e) {
            log.error("Error al hash con PBKDF2", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }

    /**
     * BUENA PRÁCTICA 3: Cifrado AES con modo GCM (proporciona autenticación)
     */
    @PostMapping("/good/encrypt-aes-gcm")
    public ResponseEntity<Map<String, String>> goodEncryptAESGCM(@RequestBody Map<String, String> payload) {
        try {
            String textToEncrypt = payload.get("text");

            // SEGURO: Usando AES/GCM con IV aleatorio y clave generada
            Map<String, String> encryptionResult = cryptographicService.encryptWithAESGCM(textToEncrypt);

            return ResponseEntity.ok(encryptionResult);
        } catch (Exception e) {
            log.error("Error al encriptar con AES/GCM", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }

    /**
     * BUENA PRÁCTICA 4: Uso de CBC con IV aleatorio
     */
    @PostMapping("/good/encrypt-aes-cbc")
    public ResponseEntity<Map<String, String>> goodEncryptAESCBC(@RequestBody Map<String, String> payload) {
        try {
            String textToEncrypt = payload.get("text");

            // SEGURO: Usando AES/CBC con IV aleatorio
            Map<String, String> encryptionResult = cryptographicService.encryptWithAESCBC(textToEncrypt);

            return ResponseEntity.ok(encryptionResult);
        } catch (Exception e) {
            log.error("Error al encriptar con AES/CBC", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }

    /**
     * BUENA PRÁCTICA 5: Verificación de contraseñas con BCrypt
     */
    @PostMapping("/good/verify-password")
    public ResponseEntity<Map<String, Object>> goodVerifyPassword(@RequestBody Map<String, String> payload) {
        String rawPassword = payload.get("password");
        String hashedPassword = payload.get("hashedPassword");

        boolean matches = cryptographicService.verifyBCryptPassword(rawPassword, hashedPassword);

        Map<String, Object> response = new HashMap<>();
        response.put("matches", matches);
        response.put("method", "BCrypt verification (SEGURO)");

        return ResponseEntity.ok(response);
    }
}