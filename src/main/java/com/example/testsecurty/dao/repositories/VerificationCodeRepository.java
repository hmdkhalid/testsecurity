package com.example.testsecurty.dao.repositories;

import com.example.testsecurty.dao.entities.VerificationCode;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.Optional;

@Repository
public interface VerificationCodeRepository extends JpaRepository<VerificationCode, Long> {

    Optional<VerificationCode> findByEmailAndCode(String email, String code);

    void deleteByEmail(String email);

    void deleteByExpiryDateBefore(LocalDateTime now);
}
