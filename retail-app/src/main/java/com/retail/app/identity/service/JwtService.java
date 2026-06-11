package com.retail.app.identity.service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service
public class JwtService {

    // Секретний ключ повинен бути мінімум 256 біт (32 символи) у Base64 кодуванні
    // Для локального старту закладемо дефолтний ключ, але на проді зчитаємо з конфігу
    @Value("${app.jwt.secret:404E635266556A586E3272357538782F413F4428472B4B6250645367566B5970}")
    private String secretKey;

    @Value("${app.jwt.expiration:86400000}") // 24 години в мілісекундах
    private long jwtExpiration;

    // 1. Генерація токена для користувача
    public String generateToken(UserDetails userDetails) {
        Map<String, Object> extraClaims = new HashMap<>();
        // Закидуємо ролі користувача в токен, щоб фронтенд або шлюз могли їх читати без запиту в БД
        var roles = userDetails.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .toList();
        extraClaims.put("roles", roles);

        return buildToken(extraClaims, userDetails.getUsername(), jwtExpiration);
    }

    private String buildToken(Map<String, Object> extraClaims, String username, long expiration) {
        return Jwts.builder()
                .claims(extraClaims)
                .subject(username)
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + expiration))
                .signWith(getSigningKey()) // Новий JJWT сам розуміє алгоритм за розміром ключа (HS256)
                .compact();
    }

    // 2. Валідація токена
    public boolean isTokenValid(String token, UserDetails userDetails) {
        final String username = extractUsername(token);
        return (username.equals(userDetails.getUsername())) && !isTokenExpired(token);
    }

    // 3. Витягування логіну (Subject) з токена
    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    // Повністю новий синтаксис версії JJWT 0.12.x
    private Claims extractAllClaims(String token) {
        return Jwts.parser()
                .verifyWith(getSigningKey()) // Замість колишнього setSigningKey()
                .build()
                .parseSignedClaims(token)    // Замість колишнього parseClaimsJws()
                .getPayload();               // Замість колишнього getBody()
    }

    private SecretKey getSigningKey() {
        byte[] keyBytes = Decoders.BASE64.decode(secretKey);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}