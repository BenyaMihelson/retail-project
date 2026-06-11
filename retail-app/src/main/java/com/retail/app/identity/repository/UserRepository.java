package com.retail.app.identity.repository;

import com.retail.app.identity.domain.UserEmployee;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<UserEmployee, Long> {

    // Цей метод Спрінг Security смикатиме при кожному вході користувача
    Optional<UserEmployee> findByUsername(String username);

    boolean existsByUsername(String username);
    boolean existsByEmail(String email);
}