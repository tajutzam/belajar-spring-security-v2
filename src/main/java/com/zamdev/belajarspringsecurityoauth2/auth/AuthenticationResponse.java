package com.zamdev.belajarspringsecurityoauth2.auth;


import lombok.*;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class AuthenticationResponse {

    private String token;

}
