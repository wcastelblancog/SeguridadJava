package com.example.seguridad.model;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Entity
@Table(name = "encryption_keys")
@Data
@NoArgsConstructor
@AllArgsConstructor
public class EncryptionKey {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(unique = true, nullable = false)
    private String keyId;

    @Column(nullable = false)
    private String algorithm;

    @Column(nullable = false)
    @Lob
    private byte[] keyBytes;

    @Column(nullable = false)
    private LocalDateTime createdAt;

    private LocalDateTime expiresAt;

    private boolean revoked = false;
}