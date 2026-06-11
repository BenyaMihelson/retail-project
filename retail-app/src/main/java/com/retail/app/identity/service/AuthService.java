package com.retail.app.identity.service;

import com.retail.app.identity.domain.Role;
import com.retail.app.identity.domain.UserEmployee;
import com.retail.app.identity.dto.AuthResponse;
import com.retail.app.identity.dto.LoginRequest;
import com.retail.app.identity.dto.RegisterRequest;
import com.retail.app.identity.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Set;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;
    private final IdentityUserDetailsService userDetailsService;


    @Transactional
    public AuthResponse register(RegisterRequest request) {
        // 1. Перевіряємо унікальність логіну та пошти
        if (userRepository.existsByUsername(request.username())) {
            throw new IllegalArgumentException("Username '" + request.username() + "' вже зайнятий");
        }
        if (userRepository.existsByEmail(request.email())) {
            throw new IllegalArgumentException("Email '" + request.email() + "' вже зареєстрований");
        }

        // 2. Створюємо нового працівника
        UserEmployee employee = new UserEmployee();
        employee.setUsername(request.username());
        employee.setEmail(request.email());

        // Хешуємо пароль перед збереженням!
        employee.setPassword(passwordEncoder.encode(request.password()));

        // Для старту дамо йому роль USER. Сюди ж можна додати логіку призначення ROLE_ADMIN
        employee.setRoles(Set.of(Role.ROLE_USER));

        userRepository.save(employee);

        // 3. Генеруємо JWT токен для щойно створеного користувача
        var userDetails = userDetailsService.loadUserByUsername(employee.getUsername());
        String jwtToken = jwtService.generateToken(userDetails);

        return new AuthResponse(jwtToken);
    }

    public AuthResponse login(LoginRequest request) {
        // Цей метод магічно перевірить пароль через архітектуру Spring Security
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(request.username(), request.password())
        );

        // Якщо автентифікація пройшла успішно — генеруємо токен
        var userDetails = userDetailsService.loadUserByUsername(request.username());
        String jwtToken = jwtService.generateToken(userDetails);

        return new AuthResponse(jwtToken);
    }
}