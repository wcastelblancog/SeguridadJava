package com.example.seguridad;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;

@SpringBootApplication
@EnableMethodSecurity
public class SeguridadApplication {
	public static void main(String[] args) {
		SpringApplication.run(SeguridadApplication.class, args);
	}
}
