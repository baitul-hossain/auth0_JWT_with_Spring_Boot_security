package com.springsecurity.jwt.springsecurityjwt.repository;

import com.springsecurity.jwt.springsecurityjwt.model.User;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepo extends JpaRepository<User, Long> {

    User findByUsername(String username);
}
