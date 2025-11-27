package com.example.testsecurty.Services;

import com.example.testsecurty.dao.entities.PasswordResetToken;
import com.example.testsecurty.dao.entities.User;
import com.example.testsecurty.dao.repositories.PasswordResetTokenRepository;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class PasswordResetService {

    private static final Logger log = LoggerFactory.getLogger(PasswordResetService.class);

    private final PasswordResetTokenRepository tokenRepository;
    private final UserService userService;
    private final EmailService emailService;
    private final PasswordEncoder passwordEncoder;

    @Transactional
    public void initiatePasswordReset(String email) {
        User user = userService.getUserByEmail(email)
                .orElseThrow(() -> new RuntimeException("Aucun compte associé à cet email"));

        tokenRepository.deleteByEmail(email);

        String token = UUID.randomUUID().toString();

        PasswordResetToken resetToken = new PasswordResetToken(token, email);
        tokenRepository.save(resetToken);

        emailService.sendPasswordResetEmail(email, token);

        log.info("✅ Token de réinitialisation généré pour : {}", email);
    }

    @Transactional
    public void resetPassword(String token, String newPassword) {
        PasswordResetToken resetToken = tokenRepository.findByToken(token)
                .orElseThrow(() -> new RuntimeException("Token invalide"));

        if (resetToken.isExpired()) {
            throw new RuntimeException("Ce lien a expiré. Veuillez faire une nouvelle demande.");
        }

        if (resetToken.isUsed()) {
            throw new RuntimeException("Ce lien a déjà été utilisé");
        }

        User user = userService.getUserByEmail(resetToken.getEmail())
                .orElseThrow(() -> new RuntimeException("Utilisateur introuvable"));

        user.setPassword(passwordEncoder.encode(newPassword));
        userService.saveUser(user);

        resetToken.setUsed(true);
        tokenRepository.save(resetToken);

        log.info("✅ Mot de passe réinitialisé pour : {}", user.getEmail());
    }

    @Transactional
    public void cleanExpiredTokens() {
        tokenRepository.deleteByExpiryDateBefore(LocalDateTime.now());
        log.info("🧹 Tokens expirés nettoyés");
    }
}