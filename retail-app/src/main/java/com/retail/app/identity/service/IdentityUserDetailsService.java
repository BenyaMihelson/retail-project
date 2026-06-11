package com.retail.app.identity.service;

import com.retail.app.identity.domain.UserEmployee;
import com.retail.app.identity.repository.UserRepository;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.stream.Collectors;

@Service
public class IdentityUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    public IdentityUserDetailsService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    @Transactional(readOnly = true)
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        // 1. Шукаємо юзера в нашій базі даних
        UserEmployee domainUserEmployee = userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found with username: " + username));

        // 2. Мапимо наші Enum-ролі (ROLE_ADMIN і т.д.) у GrantedAuthority, які розуміє Spring Security
        var authorities = domainUserEmployee.getRoles().stream()
                .map(role -> new SimpleGrantedAuthority(role.name()))
                .collect(Collectors.toList());

        // 3. Повертаємо стандартну спрінгову реалізацію UserDetails
        return User.builder()
                .username(domainUserEmployee.getUsername())
                .password(domainUserEmployee.getPassword()) // тут передається захешований пароль
                .disabled(!domainUserEmployee.isEnabled())   // якщо юзер заблокований — спрінг не пустить
                .authorities(authorities)
                .build();
    }
}