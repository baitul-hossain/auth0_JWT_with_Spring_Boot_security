package com.springsecurity.jwt.springsecurityjwt.repository;

import com.springsecurity.jwt.springsecurityjwt.model.Role;
import org.springframework.data.jpa.repository.JpaRepository;

public interface RoleRepo extends JpaRepository<Role, Long> {
    Role findByName(String name);
}
