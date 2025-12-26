package com.example.spring_security_jwt.security;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.security.SignatureException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;
import java.util.stream.Collectors;

public class JWTFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain
    ) throws ServletException, IOException {

        String header = request.getHeader(JWTCreator.HEADER_AUTHORIZATION);

        try {
            if (header != null && header.startsWith(SecurityConfig.PREFIX)) {
                // 🔐 Token existe e começa com "Bearer "
                JWTObject tokenObject = JWTCreator.create(header, SecurityConfig.PREFIX, SecurityConfig.KEY);

                List<SimpleGrantedAuthority> authorities = tokenObject.getRoles().stream()
                        .map(role -> new SimpleGrantedAuthority("ROLE_" + role))
                        .collect(Collectors.toList());

                UsernamePasswordAuthenticationToken authentication =
                        new UsernamePasswordAuthenticationToken(
                                tokenObject.getSubject(),
                                null,
                                authorities
                        );

                SecurityContextHolder.getContext().setAuthentication(authentication);
            } else {
                // ✅ NÃO existe token ou formato inválido -> limpa contexto
                SecurityContextHolder.clearContext();
            }
        } catch (ExpiredJwtException | UnsupportedJwtException | MalformedJwtException | SignatureException e) {
            // ⚠️ Token inválido: apenas limpa o contexto e segue como anônimo.
            SecurityContextHolder.clearContext();
        }

        filterChain.doFilter(request, response);
    }
}
