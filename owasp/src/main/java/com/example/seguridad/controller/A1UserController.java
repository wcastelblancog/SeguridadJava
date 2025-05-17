package com.example.seguridad.controller;

import com.example.seguridad.model.User;
import com.example.seguridad.model.UserRole;
import com.example.seguridad.repository.UserRepository;
import com.example.seguridad.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api")
@RequiredArgsConstructor
public class A1UserController {

    private final UserRepository userRepository;
    private final UserService userService;

    /**
     * VULNERABLE: Permite a cualquier usuario acceder a datos de cualquier usuario
     * Problema: No verifica si el usuario autenticado tiene permisos para acceder a estos datos
     */
    @GetMapping("/vulnerable/users/{id}")
    public ResponseEntity<User> getUser(@PathVariable Long id) {
        return userRepository.findById(id)
                .map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }

    /**
     * VULNERABLE: Permite a cualquier usuario acceder a todos los usuarios
     * Problema: No verifica permisos ni roles del usuario
     */
    @GetMapping("/vulnerable/users")
    public List<User> getAllUsers() {
        return userRepository.findAll();
    }

    /**
     * VULNERABLE: Permite actualizar usuarios sin verificar permisos
     * Problema: Un usuario puede actualizar datos de otro usuario
     */
    @PutMapping("/vulnerable/users/{id}")
    public ResponseEntity<User> updateUser(@PathVariable Long id, @RequestBody User user) {
        return userRepository.findById(id)
                .map(existingUser -> {
                    existingUser.setName(user.getName());
                    existingUser.setEmail(user.getEmail());
                    // Incluso se puede actualizar el rol sin verificación
                    existingUser.setRole(user.getRole());
                    return ResponseEntity.ok(userRepository.save(existingUser));
                })
                .orElse(ResponseEntity.notFound().build());
    }


    /**
     * VULNERABLE: Control de acceso basado en parámetros manipulables por el cliente
     * Problema: El cliente puede enviar el parámetro isAdmin=true
     */
    @GetMapping("/vulnerable/admin-data")
    public ResponseEntity<String> getAdminData(@RequestParam boolean isAdmin) {
        if (isAdmin) {
            return ResponseEntity.ok("Datos sensibles de administrador");
        } else {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body("Acceso denegado");
        }
    }

    /**
     * VULNERABLE: URLs predecibles que exponen recursos sensibles
     * Problema: URL fácil de adivinar que expone datos sensibles
     */
    @GetMapping("/vulnerable/internal-reports")
    public ResponseEntity<String> getInternalReports() {
        return ResponseEntity.ok("Informes internos confidenciales...");
    }

    /**
     * SEGURO: Acceso a datos de usuario con verificación de identidad
     * Solución: Verifica que el usuario solo pueda acceder a sus propios datos o sea admin
     */
    @GetMapping("/secure/users/{id}")
    public ResponseEntity<User> getUserSecurely(@PathVariable Long id) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        User currentUser = userService.getCurrentUser(auth);

        // Verificación de acceso: solo el propio usuario o un administrador puede ver los datos
        if (currentUser.getId().equals(id) || currentUser.getRole() == UserRole.ADMIN) {
            return userRepository.findById(id)
                    .map(ResponseEntity::ok)
                    .orElse(ResponseEntity.notFound().build());
        } else {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
        }
    }

    /**
     * SEGURO: Acceso a todos los usuarios solo para administradores
     * Solución: Usa anotación de Spring Security para restringir acceso
     */
    @GetMapping("/secure/users")
    @PreAuthorize("hasRole('ADMIN')")
    public List<User> getAllUsersSecurely() {
        return userRepository.findAll();
    }

    /**
     * SEGURO: Actualización de usuarios con verificación de identidad
     * Solución: Verifica que solo el propio usuario o un admin pueda actualizar datos
     */
    @PutMapping("/secure/users/{id}")
    public ResponseEntity<User> updateUserSecurely(@PathVariable Long id, @RequestBody User user) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        User currentUser = userService.getCurrentUser(auth);

        if (currentUser.getId().equals(id) || currentUser.getRole() == UserRole.ADMIN) {
            return userRepository.findById(id)
                    .map(existingUser -> {
                        existingUser.setName(user.getName());
                        existingUser.setEmail(user.getEmail());

                        // Solo un admin puede cambiar roles
                        if (currentUser.getRole() == UserRole.ADMIN) {
                            existingUser.setRole(user.getRole());
                        }

                        return ResponseEntity.ok(userRepository.save(existingUser));
                    })
                    .orElse(ResponseEntity.notFound().build());
        } else {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
        }
    }

    /**
     * SEGURO: Acceso a datos sensibles basado en roles en la autenticación
     * Solución: Verifica rol en el contexto de seguridad en lugar de confiar en parámetros del cliente
     */
    @GetMapping("/secure/admin-data")
    public ResponseEntity<String> getAdminDataSecurely() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        User currentUser = userService.getCurrentUser(auth);

        if (currentUser.getRole() == UserRole.ADMIN) {
            return ResponseEntity.ok("Datos sensibles de administrador");
        } else {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body("Acceso denegado");
        }
    }

    /**
     * SEGURO: Endpoints para recursos sensibles con autorización adecuada
     * Solución: Protege recursos sensibles con anotaciones de Spring Security
     */
    @GetMapping("/secure/internal-reports")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<String> getInternalReportsSecurely() {
        return ResponseEntity.ok("Informes internos confidenciales...");
    }
}