package com.example.spring_security_jwt.service;

import com.example.spring_security_jwt.model.User;
import com.example.spring_security_jwt.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class UserService {
    @Autowired
    private UserRepository repository;
    @Autowired
    private PasswordEncoder encoder;

    public User createUser(User user){
        String pass = user.getPassword();
        //criptografando antes de salvar no Banco
        user.setPassword(encoder.encode(pass));
        
        // Adiciona a role padrão "USERS" se nenhuma role for fornecida
        if (user.getRoles() == null || user.getRoles().isEmpty()) {
            user.getRoles().add("USERS");
        }
        
        return repository.save(user);
    }

    public List<User> getUsers() {
        return repository.findAll();
    }
}
