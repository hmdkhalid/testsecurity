package com.example.testsecurty.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
public class UserDTO {

    private Long id; // utilisé pour update

    @NotBlank(message = "Username is required")
    private String username;

    @Email(message = "Email invalid")
    @NotBlank(message = "Email is required")
    private String email;

    @NotBlank(message = "Role is required")
    private String role;

    // ⚠️ Mot de passe non obligatoire pour update
    private String password;
}
