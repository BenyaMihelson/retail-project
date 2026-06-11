package com.retail.app.identity.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity // Дозволяє використовувати @PreAuthorize("hasRole('ADMIN')") на контролерах
public class SecurityConfig {

    private final JwtAuthenticationFilter jwtAuthFilter;
    private final UserDetailsService userDetailsService;

    public SecurityConfig(JwtAuthenticationFilter jwtAuthFilter, UserDetailsService userDetailsService) {
        this.jwtAuthFilter = jwtAuthFilter;
        this.userDetailsService = userDetailsService;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                // 1. Вимикаємо CSRF, бо ми використовуємо STATELESS JWT (токени захищені від CSRF за своєю природою)
                .csrf(AbstractHttpConfigurer::disable)

                // 2. Налаштовуємо правила доступу до ендпоінтів
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/api/auth/**").permitAll() // Дозволяємо вхід і реєстрацію всім
                        .anyRequest().authenticated()               // Всі інші запити вимагають авторизації
                )

                // 3. Переводимо сесії в режим STATELESS (нічого не зберігаємо на сервері, як у Keycloak)
                .sessionManagement(session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                )

                // 4. Вказуємо наш AuthenticationProvider
                .authenticationProvider(authenticationProvider())

                // 5. Вставляємо наш JWT фільтр ПЕРЕД стандартним UsernamePasswordAuthenticationFilter
                .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    // Бін для перевірки паролів (AuthenticationManager буде його використовувати)
    @Bean
    public AuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider(userDetailsService);
       // authProvider.setUserDetailsService(userDetailsService); // Наш IdentityUserDetailsService
        authProvider.setPasswordEncoder(passwordEncoder());     // Наш BCrypt
        return authProvider;
    }

    // Головний менеджер автентифікації, який ми будемо викликати в AuthController для логіну
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }

    // Надійний шифратор паролів
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(); // Стандарт індустрії (SHA-256 + сіль під капотом)
    }
}