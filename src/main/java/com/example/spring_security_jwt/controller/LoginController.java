package com.example.spring_security_jwt.controller;

import com.example.spring_security_jwt.dtos.Login;
import com.example.spring_security_jwt.dtos.Sessao;
import com.example.spring_security_jwt.model.User;
import com.example.spring_security_jwt.repository.UserRepository;
import com.example.spring_security_jwt.security.JWTCreator;
import com.example.spring_security_jwt.security.JWTObject;
import com.example.spring_security_jwt.security.SecurityConfig;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Date;

@RestController
@RequestMapping("/login")
public class LoginController {
    @Autowired
    private PasswordEncoder encoder;
    @Autowired
    private SecurityConfig securityConfig;
    @Autowired
    private UserRepository repository;

    @PostMapping
    public Sessao logar(@RequestBody Login login){
        User user = repository.findByUsername(login.getUsername());
        if(user!=null) {
            boolean passwordOk = encoder.matches(login.getPassword(), user.getPassword());
            if (!passwordOk) {
                throw new RuntimeException("Senha inválida para o login: " + login.getUsername());
            }
            Sessao sessao = new Sessao();
            sessao.setLogin(user.getUsername());

            JWTObject jwtObject = new JWTObject();
            jwtObject.setSubject(user.getUsername()); // <-- CORREÇÃO APLICADA AQUI
            jwtObject.setIssuedAt(new Date(System.currentTimeMillis()));
            jwtObject.setExpiration(new Date(System.currentTimeMillis() + SecurityConfig.EXPIRATION));
            jwtObject.setRoles(user.getRoles());

            sessao.setToken(JWTCreator.create(SecurityConfig.PREFIX, SecurityConfig.KEY, jwtObject));
            return sessao;
        }else {
            throw new RuntimeException("Erro ao tentar fazer login");
        }
    }
}
