package com.example.spring_security_jwt.security;

import java.util.Arrays;
import java.util.Date;
import java.util.List;

public class JWTObject {
    private String subject; // nome  do usuario
    private Date issudAt; //data de criação do token
    private Date expiration; // data do token
    private static List<String> roles; // perfis de acesso

    //getters e setters
    public String getSubject() {
        return subject;
    }

    public void setSubject(String subject) {
        this.subject = subject;
    }

    public Date getIssudAt() {
        return issudAt;
    }


    public void setIssuedAt(Date issuedAt) {
        this.issudAt = issudAt;

    }

    public Date getExpiration() {
        return expiration;
    }

    public void setExpiration(Date expiration) {
        this.expiration = expiration;
    }

    public static List<String> getRoles() {
        return roles;
    }

    public void setRoles(List<String> roles) {
        this.roles = roles;
    }
    //getters e setters

    public void setRoles(String... roles){
         this.roles = Arrays.asList(roles);
     }

}
