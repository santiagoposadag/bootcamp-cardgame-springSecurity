package org.example.cardgame.application.command.security.user;


import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class SecurityUser {

    private String id;
    private String username;
    private String password;
    private String email;

}
