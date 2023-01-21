package com.zamdev.belajarspringsecurityoauth2.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

// beri component anotations agar menjadi bean
@Component
@RequiredArgsConstructor
// filter setiap request , dengan cara extends OncePerRequestFilter
public class JwtAuthenticationFilter  extends OncePerRequestFilter {

    @Autowired
    private JwtService jwtService;
    private final UserDetailsService userDetailService;

    @Override
    protected void doFilterInternal
            (@NonNull HttpServletRequest request
                    , @NonNull HttpServletResponse response
                    , @NonNull FilterChain filterChain) throws ServletException, IOException
    {
        // buat header karena token akan kita kirim melalui header
        final String authHeader = request.getHeader("Authorization");
        final String jwtToken ;
        final String userEmail;
        if(authHeader==null || !authHeader.startsWith("Bearer ")){
            // jika iya maka teruskan filter nya
            filterChain.doFilter(request , response);
            return;
        }
        // extract token dari header
        // dimulai dari 7 karena bearer dan spasi
        jwtToken = authHeader.substring(7);
        // ambil useremail dari jwt token
        userEmail = jwtService.ectractUsername(jwtToken);
        // jika useremail ada dan belum di authentication maka masuk ke if
        if(userEmail !=null && SecurityContextHolder.getContext().getAuthentication() == null){
            // buat userdetail dari userdetails
            UserDetails userDetails = this.userDetailService.loadUserByUsername(userEmail);
            if(jwtService.isTokenValid(jwtToken , userDetails)){
                // jika token valid maka update seciroty menggunakan usernamePasswordAuthentication
                UsernamePasswordAuthenticationToken authenticationToken =
                        new UsernamePasswordAuthenticationToken(
                                userDetails.getUsername()
                                , null ,
                                userDetails.getAuthorities()
                        );
                authenticationToken.setDetails(
                        new WebAuthenticationDetailsSource()
                                .buildDetails(request)

                );
                // update security contect holder
                SecurityContextHolder.getContext().setAuthentication(authenticationToken);
            }
        }
        filterChain.doFilter(request , response);
    }
}
