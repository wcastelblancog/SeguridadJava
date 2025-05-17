package com.example.seguridad.config;

import com.example.seguridad.model.User;
import com.example.seguridad.model.UserRole;
import com.example.seguridad.repository.UserRepository;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class DataInitializer {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    @PostConstruct
    public void init() {
        // Crear usuarios para pruebas si no existen
        if (userRepository.findByEmail("admin@example.com") == null) {
            User admin = new User();
            admin.setName("Admin");
            admin.setEmail("admin@example.com");
            admin.setPassword(passwordEncoder.encode("admin123"));
            admin.setRole(UserRole.ADMIN);
            userRepository.save(admin);
        }

        if (userRepository.findByEmail("user1@example.com") == null) {
            User user1 = new User();
            user1.setName("Usuario 1");
            user1.setEmail("user1@example.com");
            user1.setPassword(passwordEncoder.encode("user123"));
            user1.setRole(UserRole.USER);
            userRepository.save(user1);
        }

        if (userRepository.findByEmail("user2@example.com") == null) {
            User user2 = new User();
            user2.setName("Usuario 2");
            user2.setEmail("user2@example.com");
            user2.setPassword(passwordEncoder.encode("user123"));
            user2.setRole(UserRole.USER);
            userRepository.save(user2);
        }
    }
}