package com.example.seguridad.controller;

import com.example.seguridad.dto.SearchDTO;
import com.example.seguridad.dto.UserDTO;
import com.example.seguridad.model.UserInject;
import com.example.seguridad.repository.UserRepositoryInject;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import jakarta.persistence.Query;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.*;

import java.sql.PreparedStatement;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Controlador que demuestra ejemplos vulnerables y seguros
 * relacionados con OWASP Top 10 A03: Injection (Inyección)
 */
@RestController
@RequestMapping("/api/injection")
@RequiredArgsConstructor
@Slf4j
public class A3InjectionController {

    private final JdbcTemplate jdbcTemplate;
    private final UserRepositoryInject userRepositoryInject;

    @PersistenceContext
    private EntityManager entityManager;

    /**
     * EJEMPLO VULNERABLE 1: SQL Injection directo en consulta
     * Este endpoint es vulnerable porque concatena el input del usuario directamente en la consulta SQL
     *
     * Prueba con Postman:
     * GET /api/injection/vulnerable/users?username=admin
     * Para explotar: /api/injection/vulnerable/users?username=admin' OR '1'='1
     */
    @GetMapping("/vulnerable/users")
    public ResponseEntity<List<Map<String, Object>>> getUsersVulnerable(@RequestParam String username) {
        // PELIGROSO: Concatenación directa de parámetro en consulta SQL
        String sql = "SELECT * FROM usersinject WHERE username = '" + username + "'";
        log.info("Ejecutando consulta vulnerable: {}", sql);

        List<Map<String, Object>> results = jdbcTemplate.queryForList(sql);
        log.info("Resulatdo: {}", results);
        return ResponseEntity.ok(results);
    }

    /**
     * EJEMPLO VULNERABLE 2: SQL Injection con JPQL
     * Este endpoint es vulnerable porque construye dinámicamente una consulta JPQL con la entrada del usuario
     *
     * Prueba con Postman:
     * POST /api/injection/vulnerable/search
     * Body: {"searchTerm": "admin"}
     * Para explotar: {"searchTerm": "admin' OR '1'='1"}
     */
    @PostMapping("/vulnerable/search")
    public ResponseEntity<List<UserInject>> searchUsersVulnerable(@RequestBody SearchDTO searchDTO) {
        try {
            // PELIGROSO: Construcción dinámica de consulta JPQL
            String jpqlQuery = "SELECT u FROM UserInject u WHERE u.username = '"
                    + searchDTO.getSearchTerm() + "' OR u.email = '"
                    + searchDTO.getSearchTerm() + "'";
            log.info("Ejecutando consulta JPQL vulnerable: {}", jpqlQuery);

            Query query = entityManager.createQuery(jpqlQuery);
            List<UserInject> results = query.getResultList();
            return ResponseEntity.ok(results);
        } catch (Exception e) {
            // Mostrar el error para debugging
            log.error("Error al ejecutar consulta JPQL: {}", e.getMessage());
            return ResponseEntity.badRequest().build();
        }
    }

    /**
     * EJEMPLO SEGURO 1: Uso de PreparedStatement
     * Este endpoint es seguro porque usa PreparedStatement con parámetros
     *
     * Prueba con Postman:
     * GET /api/injection/safe/users?username=admin
     * Intenta: /api/injection/safe/users?username=admin' OR '1'='1  (No funcionará la inyección)
     */
    @GetMapping("/safe/users")
    public ResponseEntity<List<Map<String, Object>>> getUsersSafe(@RequestParam String username) {
        List<Map<String, Object>> results = new ArrayList<>();

        // SEGURO: Uso de PreparedStatement con parámetros
        String sql = "SELECT * FROM usersinject WHERE username = ?";
        log.info("Ejecutando consulta segura con parámetro: {}", username);

        jdbcTemplate.query(
                connection -> {
                    PreparedStatement ps = connection.prepareStatement(sql);
                    ps.setString(1, username);
                    return ps;
                },
                rs -> {
                    Map<String, Object> row = new HashMap<>();
                    row.put("id", rs.getLong("id"));
                    row.put("username", rs.getString("username"));
                    row.put("email", rs.getString("email"));
                    results.add(row);
                }
        );

        return ResponseEntity.ok(results);
    }

    /**
     * EJEMPLO SEGURO 2: Uso de JPA con parámetros nombrados
     * Este endpoint es seguro porque utiliza parámetros nombrados en JPQL
     *
     * Prueba con Postman:
     * POST /api/injection/safe/search
     * Body: {"searchTerm": "admin"}
     * Intenta: {"searchTerm": "admin' OR '1'='1"}  (No funcionará la inyección)
     */
    @PostMapping("/safe/search")
    public ResponseEntity<List<UserInject>> searchUsersSafe(@RequestBody SearchDTO searchDTO) {
        // SEGURO: Uso de parámetros nombrados en JPQL
        String jpqlQuery = "SELECT u FROM UserInject u WHERE u.username LIKE :searchPattern OR u.email LIKE :searchPattern";
        log.info("Ejecutando consulta JPQL segura con parámetro: {}", searchDTO.getSearchTerm());

        String searchPattern = "%" + searchDTO.getSearchTerm() + "%";
        Query query = entityManager.createQuery(jpqlQuery)
                .setParameter("searchPattern", searchPattern);

        List<UserInject> results = query.getResultList();
        return ResponseEntity.ok(results);
    }

    /**
     * EJEMPLO SEGURO 3: Uso de Spring Data JPA Repository
     * Este endpoint es seguro porque utiliza métodos de repositorio Spring Data
     *
     * Prueba con Postman:
     * GET /api/injection/safe/repository?username=admin
     */
    @GetMapping("/safe/repository")
    public ResponseEntity<List<UserInject>> getUsersWithRepository(@RequestParam String username) {
        // SEGURO: Uso de métodos del repositorio Spring Data JPA
        log.info("Buscando usuarios con repositorio Spring Data: {}", username);
        List<UserInject> users = userRepositoryInject.findByUsernameContaining(username);
        return ResponseEntity.ok(users);
    }

    /**
     * Endpoint para crear un usuario que podemos usar en las pruebas
     */
    @PostMapping("/users")
    public ResponseEntity<UserInject> createUser(@RequestBody UserDTO userDTO) {
        UserInject user = new UserInject();
        user.setUsername(userDTO.getUsername());
        user.setEmail(userDTO.getEmail());
        user.setPassword(userDTO.getPassword());
        UserInject savedUser = userRepositoryInject.save(user);
        return ResponseEntity.ok(savedUser);
    }
}