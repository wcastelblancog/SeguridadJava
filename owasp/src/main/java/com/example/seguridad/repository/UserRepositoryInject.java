package com.example.seguridad.repository;

import com.example.seguridad.model.UserInject;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface UserRepositoryInject extends JpaRepository<UserInject, Long> {

    List<UserInject> findByUsernameContaining(String username);

    List<UserInject> findByEmailContaining(String email);
}
