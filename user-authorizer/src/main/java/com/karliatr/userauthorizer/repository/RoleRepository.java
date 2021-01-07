package com.karliatr.userauthorizer.repository;

import com.karliatr.userauthorizer.models.ERole;
import com.karliatr.userauthorizer.models.Role;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface RoleRepository extends JpaRepository<Role, Long> {
    Optional<Role> findByName(ERole name);
}
