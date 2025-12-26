package com.example.spring_security_jwt.security;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;

import javax.crypto.SecretKey;
import java.util.Base64;
import java.util.List;
import java.util.stream.Collectors;

public class JWTCreator {

    public static final String HEADER_AUTHORIZATION = "Authorization";
    public static final String ROLES_AUTHORITIES = "authorities";

    // 🔐 CHAVE SEGURA (Base64)
    private static final String SECRET_KEY =
            "dGhpc0lzQVN1cGVyU2VjcmV0S2V5Rm9ySldUVXNpbmdIUzUxMg==";

    private static SecretKey getSigningKey() {
        byte[] keyBytes = Base64.getDecoder().decode(SECRET_KEY);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    public static String create(String prefix, JWTObject jwtObject) {

        String token = Jwts.builder()
                .setSubject(jwtObject.getSubject())
                .setIssuedAt(jwtObject.getIssuedAt())
                .setExpiration(jwtObject.getExpiration())
                .claim(ROLES_AUTHORITIES, checkRoles(jwtObject.getRoles()))
                .signWith(getSigningKey(), SignatureAlgorithm.HS512)
                .compact();

        return prefix + " " + token;
    }

    public static JWTObject create(String token, String prefix)
            throws ExpiredJwtException, UnsupportedJwtException, MalformedJwtException {

        JWTObject object = new JWTObject();

        token = token.replace(prefix, "").trim();

        Claims claims = Jwts.parserBuilder()
                .setSigningKey(getSigningKey())
                .build()
                .parseClaimsJws(token)
                .getBody();

        object.setSubject(claims.getSubject());
        object.setExpiration(claims.getExpiration());
        object.setIssuedAt(claims.getIssuedAt());
        object.setRoles((List<String>) claims.get(ROLES_AUTHORITIES));

        return object;
    }

    private static List<String> checkRoles(List<String> roles) {
        return roles.stream()
                .map(s -> "ROLE_".concat(s.replace("ROLE_", "")))
                .collect(Collectors.toList());
    }


}
