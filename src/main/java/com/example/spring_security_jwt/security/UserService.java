package com.example.spring_security_jwt.security;

import com.example.spring_security_jwt.model.User;
import com.example.spring_security_jwt.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class UserService {
    @Autowired
    private UserRepository repository;
    @Autowired
    private PasswordEncoder encoder;
    public void createUser(User user){
        String pass = user.getPassword();
        //criptografando antes de salvar no Banco
        user.setPassword(encoder.encode(pass));
        repository.save(user);
    }
}
