package com.security.jwt.Dto;


import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class RegisterDto {
    String email;
    String password;
    String firstname;
    String lastname;
    String country;
    String role;
}
