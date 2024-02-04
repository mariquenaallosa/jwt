package com.security.jwt.Controller;

import com.security.jwt.Dto.AuthResponse;
import com.security.jwt.Dto.LoginDto;
import com.security.jwt.Dto.RegisterDto;
import com.security.jwt.Service.AuthService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import lombok.RequiredArgsConstructor;


@RestController
@RequestMapping(value = "/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;



    @PostMapping(value = "login")
    public ResponseEntity<AuthResponse> login(@RequestBody LoginDto login){
        try{
            return ResponseEntity.ok(authService.login(login));
        }catch(Exception e){
            return new ResponseEntity(e.getMessage(),HttpStatus.BAD_REQUEST);
        }
    }

    @PostMapping(value = "register")
    public ResponseEntity<AuthResponse> register(@RequestBody RegisterDto register){
        try{
            return ResponseEntity.ok(authService.register(register));
        }catch (Exception e){
            return new ResponseEntity(e.getMessage(),HttpStatus.BAD_REQUEST);
        }
    }
}
