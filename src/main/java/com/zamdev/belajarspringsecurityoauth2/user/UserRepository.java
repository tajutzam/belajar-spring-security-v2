package com.zamdev.belajarspringsecurityoauth2.user;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User , Integer> {
    // buat fungsi untuk menemukan user by email
    Optional<User> findByEmail(String email);
}
