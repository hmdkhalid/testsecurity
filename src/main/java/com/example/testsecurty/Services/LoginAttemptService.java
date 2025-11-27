package com.example.testsecurty.Services;

import org.springframework.stereotype.Service;
import java.time.LocalDateTime;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class LoginAttemptService {

    private static final int MAX_ATTEMPTS = 5;
    private static final int LOCK_TIME_MINUTES = 15;

    private final Map<String, AttemptInfo> attemptsCache = new ConcurrentHashMap<>();

    /**
     * Enregistre une tentative de connexion échouée
     */
    public void loginFailed(String key) {
        AttemptInfo info = attemptsCache.getOrDefault(key, new AttemptInfo());
        info.attempts++;
        info.lastAttempt = LocalDateTime.now();
        attemptsCache.put(key, info);

        System.out.println("⚠️ Failed login attempt for: " + key +
                " (Attempt " + info.attempts + "/" + MAX_ATTEMPTS + ")");
    }

    /**
     * Vérifie si un compte est bloqué
     */
    public boolean isBlocked(String key) {
        if (!attemptsCache.containsKey(key)) {
            return false;
        }

        AttemptInfo info = attemptsCache.get(key);

        // Vérifier si le temps de blocage est écoulé
        if (LocalDateTime.now().isAfter(info.lastAttempt.plusMinutes(LOCK_TIME_MINUTES))) {
            attemptsCache.remove(key);
            return false;
        }

        return info.attempts >= MAX_ATTEMPTS;
    }

    /**
     * Réinitialise les tentatives après un login réussi
     */
    public void loginSucceeded(String key) {
        attemptsCache.remove(key);
        System.out.println("✅ Login successful, attempts reset for: " + key);
    }

    /**
     * Classe interne pour stocker les informations de tentative
     */
    private static class AttemptInfo {
        int attempts = 0;
        LocalDateTime lastAttempt = LocalDateTime.now();
    }
}