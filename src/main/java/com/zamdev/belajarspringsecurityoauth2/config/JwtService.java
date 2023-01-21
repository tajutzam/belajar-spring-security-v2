package com.zamdev.belajarspringsecurityoauth2.config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.function.Function;


@Service
public class JwtService {


    private static final String secret_key = "2948404D6351665468576D5A7134743777217A25432A462D4A614E645267556B";

    public String ectractUsername(String jwtToken) {
        // ambil username dari jwt token yang dari header , masukan dependency jwt di pom
        // get subject is get username for user
        return extractClaim(jwtToken , Claims::getSubject);
    }

    public String generateToken(Map<String , Object> claims , UserDetails userDetails){
        // generate token dari userdatils
        return Jwts.
                builder()
                .setClaims(claims)
                // set subject diambil dari username // email
                .setClaims(claims)
                .setSubject(userDetails.getUsername())
                // set dibuat token kapan
                .setIssuedAt(new Date(System.currentTimeMillis()))
                // set expired token nya
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 24))
                // pakai signing key nya
                .signWith(getSigningKey() , SignatureAlgorithm.HS256)
                // buat menjadi token
                .compact();
    }

    // buat token generate token yang tidak memasukan map lagi
    public String generateToken(UserDetails userDetails){
        return generateToken(new HashMap<>() , userDetails);
    }
        public Claims etxraxtAllClaims(String token){
        return Jwts.parserBuilder()
                .setSigningKey(getSigningKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    // check token valid or not
    public boolean isTokenValid(String token , UserDetails userDetails){
        final String username = ectractUsername(token);
        // return true jika username dari token dan username detail service itu sama dan jika token tidak expired
        return (Objects.equals(username, userDetails.getUsername()) && !isTokenExpired(token));
    }

    private boolean isTokenExpired(String token) {
        // akan return true jika tanggal expired before tanggal sekarang
        return extractExpiration(token).before(new Date());
    }

    private Date extractExpiration(String token) {
        // get exparation menggunakan ClaimsGetExpiration
        return extractClaim(token , Claims::getExpiration);
    }

    private Key getSigningKey() {
        // get secret key
        byte[] keyBytes = Decoders.BASE64.decode(secret_key);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    public <T> T extractClaim(String token , Function<Claims , T> resolverClaims){
        final Claims claims = etxraxtAllClaims(token);
        return resolverClaims.apply(claims);
    }
}
