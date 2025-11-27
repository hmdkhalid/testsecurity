package com.example.testsecurty.Services;

import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class EmailService {

    private static final Logger log = LoggerFactory.getLogger(EmailService.class);

    private final JavaMailSender mailSender;

    @Value("${spring.mail.username}")
    private String fromEmail;

    public void sendPasswordResetEmail(String toEmail, String resetToken) {
        try {
            SimpleMailMessage message = new SimpleMailMessage();
            message.setFrom(fromEmail); // ✅ Utilise hammadikhalid0000@gmail.com
            message.setTo(toEmail);
            message.setSubject("Réinitialisation de votre mot de passe");

            String resetUrl = "http://localhost:4400/reset-password?token=" + resetToken; // ✅ Corrigé le port

            message.setText(
                    "Bonjour,\n\n" +
                            "Vous avez demandé la réinitialisation de votre mot de passe.\n\n" +
                            "Cliquez sur le lien suivant pour réinitialiser votre mot de passe :\n" +
                            resetUrl + "\n\n" +
                            "Ce lien expire dans 30 minutes.\n\n" +
                            "Si vous n'avez pas demandé cette réinitialisation, ignorez ce message.\n\n" +
                            "Cordialement,\n" +
                            "L'équipe Support"
            );

            mailSender.send(message);
            log.info("✅ Email de réinitialisation envoyé à : {}", toEmail);

        } catch (Exception e) {
            log.error("❌ Erreur lors de l'envoi de l'email : {}", e.getMessage());
            e.printStackTrace(); // ✅ Affiche la stack trace complète
            throw new RuntimeException("Impossible d'envoyer l'email");
        }
    }

    public void sendVerificationCodeEmail(String toEmail, String code) {
        try {
            SimpleMailMessage message = new SimpleMailMessage();
            message.setFrom(fromEmail);
            message.setTo(toEmail);
            message.setSubject("Votre code de vérification");

            message.setText(
                    "Bonjour,\n\n" +
                            "Votre code de vérification est :\n\n" +
                            "📱 " + code + "\n\n" +
                            "Ce code expire dans 10 minutes.\n\n" +
                            "Si vous n'avez pas demandé ce code, ignorez ce message.\n\n" +
                            "Cordialement,\n" +
                            "L'équipe Support"
            );

            mailSender.send(message);
            log.info("✅ Code de vérification envoyé à : {}", toEmail);

        } catch (Exception e) {
            log.error("❌ Erreur lors de l'envoi du code : {}", e.getMessage());
            e.printStackTrace();
            throw new RuntimeException("Impossible d'envoyer le code");
        }
    }
}