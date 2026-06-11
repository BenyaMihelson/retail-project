package com.retail.app.identity.config;

import com.retail.app.identity.domain.Role;
import com.retail.app.identity.domain.UserEmployee;
import com.retail.app.identity.repository.UserRepository;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.Set;

@Component
public class IdentityDataInitializer implements CommandLineRunner {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public IdentityDataInitializer(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public void run(String... args) throws Exception {
        String adminUsername = "superadmin";

        // 1. ЗАХИСТ: Перевіряємо, чи суперюзер вже існує в базі
        if (!userRepository.existsByUsername(adminUsername)) {

            // 2. Створюємо сутність першого адміна
            UserEmployee admin = new UserEmployee();
            admin.setUsername(adminUsername);
            admin.setEmail("admin@retail.app");

            // Хешуємо дефолтний пароль через наш BCrypt бін із SecurityConfig
            admin.setPassword(passwordEncoder.encode("Admin123"));

            admin.setEnabled(true);

            // Даємо йому повний пакет ролей
            admin.setRoles(Set.of(Role.ROLE_USER, Role.ROLE_MANAGER, Role.ROLE_ADMIN));

            // 3. Зберігаємо в базу даних
            userRepository.save(admin);

            System.out.println("=================================================");
            System.out.println(" [SUCCESS] Першого суперюзера успішно створено!");
            System.out.println(" Логін: " + adminUsername);
            System.out.println(" Пароль: Admin123");
            System.out.println("=================================================");
        } else {
            System.out.println(" [INFO] Суперюзер '" + adminUsername + "' вже існує в БД. Пропускаємо ініціалізацію.");
        }
    }
}