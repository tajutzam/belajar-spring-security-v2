package com.zamdev.belajarspringsecurityoauth2.auth;

import com.zamdev.belajarspringsecurityoauth2.config.JwtService;
import com.zamdev.belajarspringsecurityoauth2.user.Role;
import com.zamdev.belajarspringsecurityoauth2.user.User;
import com.zamdev.belajarspringsecurityoauth2.user.UserRepository;
import lombok.NoArgsConstructor;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthService {

    @Autowired
    private final UserRepository userRepository;

    @Autowired
    private final PasswordEncoder passwordEncoder;

    private final JwtService jwtService;

    private final AuthenticationManager authenticationManager;

    public AuthenticationResponse register(RegisterRequest registerRequest) {
        var user = User.builder().
                email(registerRequest.getEmail()).firstName(registerRequest.getFirstName())
                .lastName(registerRequest.getLastName())
                        .password(passwordEncoder.encode(registerRequest.getPassword())).
                role(Role.ADMIN).
                build();
        userRepository.save(user);
        var jwtToken = jwtService.generateToken(user);
        return AuthenticationResponse.builder().token(jwtToken).build();
    }

    public AuthenticationResponse login(LoginRequest loginRequest) {
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        loginRequest.getEmail() ,
                        loginRequest.getPassword()
                )
        );
        // jika password dan email benar jika salah maka  akan trow
        var user = userRepository.findByEmail(loginRequest.getEmail())
                .orElseThrow(() -> new UsernameNotFoundException("User with email not found"));
        var jwtToken = jwtService.generateToken(user);
        return AuthenticationResponse.builder().token(jwtToken).build();
    }
}
