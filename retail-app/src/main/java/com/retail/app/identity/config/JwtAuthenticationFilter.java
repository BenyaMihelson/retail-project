package com.retail.app.identity.config;

import com.retail.app.identity.service.JwtService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.jspecify.annotations.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private final UserDetailsService userDetailsService; // Спрінг сам підтягне наш IdentityUserDetailsService


    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain
    ) throws ServletException, IOException {

        // 1. Витягуємо хедер Authorization
        final String authHeader = request.getHeader("Authorization");
        final String jwt;
        final String username;

        // 2. Якщо хедера немає або він не починається з "Bearer ", то пропускаємо запит далі по ланцюжку
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }

        // 3. Вирізаємо сам токен (відраховуємо 7 символів від початку "Bearer ")
        jwt = authHeader.substring(7);

        // 4. Витягуємо username з токена за допомогою нашого JwtService
        username = jwtService.extractUsername(jwt);

        // 5. Якщо юзернейм є, але в поточному потоці (SecurityContext) аутентифікації ще немає
        if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {

            // Завантажуємо UserDetails з бази даних
            UserDetails userDetails = this.userDetailsService.loadUserByUsername(username);

            // 6. Якщо токен валідний і належить цьому користувачу
            if (jwtService.isTokenValid(jwt, userDetails)) {

                // Створюємо об'єкт аутентифікації, куди передаємо ролі (Authorities)
                UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                        userDetails,
                        null,
                        userDetails.getAuthorities()
                );

                // Додаємо деталі запиту (IP, сесія і т.д.)
                authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                // 7. Оновлюємо SecurityContext. Тепер Спрінг знає, що користувач авторизований
                SecurityContextHolder.getContext().setAuthentication(authToken);
            }
        }

        // 8. Передаємо запит далі наступним фільтрам
        filterChain.doFilter(request, response);
    }
}