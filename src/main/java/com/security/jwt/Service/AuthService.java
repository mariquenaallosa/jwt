package com.security.jwt.Service;

import com.security.jwt.Dto.AuthResponse;
import com.security.jwt.Dto.LoginDto;
import com.security.jwt.Dto.RegisterDto;
import com.security.jwt.Entity.Role;
import com.security.jwt.Entity.User;
import com.security.jwt.Repository.UserRepository;
import com.security.jwt.Security.jwt.JwtService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final JwtService jwtService;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;


    public AuthResponse login(LoginDto login){
        authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(login.getEmail(), login.getPassword()));
        UserDetails user = userRepository.findByEmail(login.getEmail()).orElseThrow();
        String token = jwtService.getToken(user);
        return AuthResponse.builder().token(token).build();
    }

    public AuthResponse resgister(RegisterDto register){
        Optional<User> userOptional = userRepository.findByEmail(register.getEmail());
        if (userOptional.isPresent()){
            throw new RuntimeException("User already exists");
        }

        User user = User.builder()
                .email(register.getEmail())
                .password(passwordEncoder.encode(register.getPassword()))
                .firstname(register.getFirstname())
                .lastname(register.getLastname())
                .country(register.getCountry())
                .role(Role.valueOf(register.getRole()))
                .build();

        userRepository.save(user);
        return AuthResponse.builder()
                .token(jwtService.getToken(user))
                .build();

    }
}
