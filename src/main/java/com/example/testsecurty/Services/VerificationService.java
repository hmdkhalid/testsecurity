package com.example.testsecurty.Services;

import com.example.testsecurty.dao.entities.VerificationCode;
import com.example.testsecurty.dao.repositories.VerificationCodeRepository;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.Random;

@Service
@RequiredArgsConstructor
public class VerificationService {

    private static final Logger log = LoggerFactory.getLogger(VerificationService.class);

    private final VerificationCodeRepository codeRepository;
    private final EmailService emailService;

    @Transactional
    public void sendVerificationCode(String email) {
        // Supprime les anciens codes pour cet email
        codeRepository.deleteByEmail(email);

        // Génère un code à 6 chiffres
        String code = generateSixDigitCode();

        // Sauvegarde le code en base
        VerificationCode verificationCode = new VerificationCode(email, code);
        codeRepository.save(verificationCode);

        // Envoie l'email
        emailService.sendVerificationCodeEmail(email, code);

        log.info("✅ Code de vérification envoyé à : {}", email);
    }

    @Transactional
    public boolean verifyCode(String email, String code) {
        VerificationCode verificationCode = codeRepository.findByEmailAndCode(email, code)
                .orElseThrow(() -> new RuntimeException("Code invalide"));

        if (verificationCode.isExpired()) {
            throw new RuntimeException("Ce code a expiré. Demandez un nouveau code.");
        }

        if (verificationCode.isUsed()) {
            throw new RuntimeException("Ce code a déjà été utilisé");
        }

        // Marque le code comme utilisé
        verificationCode.setUsed(true);
        codeRepository.save(verificationCode);

        log.info("✅ Code vérifié pour : {}", email);
        return true;
    }

    private String generateSixDigitCode() {
        Random random = new Random();
        int code = 100000 + random.nextInt(900000); // Génère un nombre entre 100000 et 999999
        return String.valueOf(code);
    }

    @Transactional
    public void cleanExpiredCodes() {
        codeRepository.deleteByExpiryDateBefore(LocalDateTime.now());
        log.info("🧹 Codes expirés nettoyés");
    }
}