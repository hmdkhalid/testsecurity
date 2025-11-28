    package com.example.testsecurty.Controller;

    import com.example.testsecurty.Services.LoginAttemptService;
    import com.example.testsecurty.Services.PasswordResetService;
    import com.example.testsecurty.Services.UserService;
    import com.example.testsecurty.Services.VerificationService;
    import com.example.testsecurty.dao.entities.User;
    import com.example.testsecurty.security.JwtService;
    import lombok.RequiredArgsConstructor;
    import org.slf4j.Logger;
    import org.slf4j.LoggerFactory;
    import org.springframework.http.ResponseEntity;
    import org.springframework.security.access.prepost.PreAuthorize;
    import org.springframework.security.authentication.AuthenticationManager;
    import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
    import org.springframework.security.core.Authentication;
    import org.springframework.security.crypto.password.PasswordEncoder;
    import org.springframework.web.bind.annotation.*;

    import java.util.HashMap;
    import java.util.List;
    import java.util.Map;

    @RestController
    @RequestMapping("/api")
    @CrossOrigin(origins = "*")
    @RequiredArgsConstructor
    public class UserController {

        private static final Logger log = LoggerFactory.getLogger(UserController.class);

        private final UserService userService;
        private final JwtService jwtService;
        private final AuthenticationManager authenticationManager;
        private final PasswordEncoder passwordEncoder;
        private final LoginAttemptService loginAttemptService;
        private final PasswordResetService passwordResetService;
        private final VerificationService verificationService ;

// TODO: test pull request


        @PostMapping("/auth/register")
        public ResponseEntity<?> register(@RequestBody User user) {
            try {
                log.info("📝 New registration attempt: username={}, email={}", user.getUsername(), user.getEmail());

                if (user.getPassword() == null || user.getPassword().isBlank()) {
                    log.warn("❌ Registration failed: password is empty");
                    return ResponseEntity.badRequest()
                            .body(Map.of("error", "Password is required"));
                }

                if (!isStrongPassword(user.getPassword())) {
                    log.warn("❌ Registration failed: password not strong enough");
                    return ResponseEntity.badRequest()
                            .body(Map.of("error", "Password must be at least 8 characters with letters and numbers"));
                }

                if (userService.existsByUsername(user.getUsername())) {
                    log.warn("❌ Registration failed: username already exists - {}", user.getUsername());
                    return ResponseEntity.badRequest()
                            .body(Map.of("error", "Username already exists"));
                }

                if (userService.existsByEmail(user.getEmail())) {
                    log.warn("❌ Registration failed: email already exists - {}", user.getEmail());
                    return ResponseEntity.badRequest()
                            .body(Map.of("error", "Email already exists"));
                }

                User savedUser = userService.saveUser(user);
                String token = jwtService.generateToken(savedUser);

                log.info("✅ Registration successful: username={}", savedUser.getUsername());

                Map<String, Object> response = new HashMap<>();
                response.put("token", token);
                response.put("username", savedUser.getUsername());
                response.put("email", savedUser.getEmail());
                response.put("role", savedUser.getRole());

                return ResponseEntity.ok(response);

            } catch (Exception e) {
                log.error("❌ Registration error: {}", e.getMessage());
                return ResponseEntity.badRequest()
                        .body(Map.of("error", "Registration failed: " + e.getMessage()));
            }
        }

        @PostMapping("/auth/login")
        public ResponseEntity<?> login(@RequestBody Map<String, String> loginRequest) {
            String login = loginRequest.get("username");
            String password = loginRequest.get("password");

            try {
                log.info("🔐 Login attempt: identifier={}", login);

                if (loginAttemptService.isBlocked(login)) {
                    log.warn("🚫 Account temporarily blocked: {}", login);
                    return ResponseEntity.status(429)
                            .body(Map.of("error", "Too many failed attempts. Please try again in 15 minutes."));
                }

                String usernameToAuth = userService.getUserByEmail(login)
                        .map(User::getUsername)
                        .orElse(login);

                Authentication authentication = authenticationManager.authenticate(
                        new UsernamePasswordAuthenticationToken(usernameToAuth, password)
                );

                User user = userService.getUserByUsername(usernameToAuth)
                        .orElseThrow(() -> new RuntimeException("User not found"));

                String token = jwtService.generateToken(user);

                loginAttemptService.loginSucceeded(login);

                log.info("✅ Login successful: username={}", user.getUsername());

                Map<String, Object> response = new HashMap<>();
                response.put("token", token);
                response.put("username", user.getUsername());
                response.put("email", user.getEmail());
                response.put("role", user.getRole());

                return ResponseEntity.ok(response);

            } catch (Exception e) {
                loginAttemptService.loginFailed(login);

                log.warn("❌ Login failed: identifier={}, error={}", login, e.getMessage());
                return ResponseEntity.status(401)
                        .body(Map.of("error", "Invalid username/email or password"));
            }
        }

        @PostMapping("/auth/forgot-password")
        public ResponseEntity<?> forgotPassword(@RequestBody Map<String, String> request) {
            String email = request.get("email");

            try {
                log.info("🔑 Password reset requested for: {}", email);
                passwordResetService.initiatePasswordReset(email);

                return ResponseEntity.ok(Map.of(
                        "message", "Si cet email existe, un lien de réinitialisation a été envoyé"
                ));

            } catch (Exception e) {
                log.error("❌ Password reset error: {}", e.getMessage());
                return ResponseEntity.ok(Map.of(
                        "message", "Si cet email existe, un lien de réinitialisation a été envoyé"
                ));
            }
        }

        @PostMapping("/auth/reset-password")
        public ResponseEntity<?> resetPassword(@RequestBody Map<String, String> request) {
            String token = request.get("token");
            String newPassword = request.get("newPassword");

            try {
                log.info("🔐 Password reset attempt with token");

                if (newPassword == null || newPassword.isBlank()) {
                    return ResponseEntity.badRequest()
                            .body(Map.of("error", "Le mot de passe est requis"));
                }

                if (!isStrongPassword(newPassword)) {
                    return ResponseEntity.badRequest()
                            .body(Map.of("error", "Le mot de passe doit contenir au moins 8 caractères avec lettres et chiffres"));
                }

                passwordResetService.resetPassword(token, newPassword);

                log.info("✅ Password successfully reset");
                return ResponseEntity.ok(Map.of(
                        "message", "Mot de passe réinitialisé avec succès"
                ));

            } catch (RuntimeException e) {
                log.error("❌ Password reset failed: {}", e.getMessage());
                return ResponseEntity.badRequest()
                        .body(Map.of("error", e.getMessage()));
            }
        }

        @PostMapping("/users")
        @PreAuthorize("hasRole('ADMIN')")
        public ResponseEntity<User> saveUser(@RequestBody User user) {
            log.info("👤 Admin creating new user: {}", user.getUsername());
            User savedUser = userService.saveUser(user);
            return ResponseEntity.ok(savedUser);
        }

        @GetMapping("/users")
        @PreAuthorize("hasRole('ADMIN')")
        public ResponseEntity<List<User>> getAllUsers() {
            log.info("📋 Admin fetching all users");
            return ResponseEntity.ok(userService.getAllUsers());
        }

        @GetMapping("/users/{id}")
        @PreAuthorize("hasAnyRole('ADMIN', 'USER')")
        public ResponseEntity<User> getUserById(@PathVariable Long id) {
            log.info("🔍 Fetching user by ID: {}", id);
            return userService.getUserById(id)
                    .map(ResponseEntity::ok)
                    .orElse(ResponseEntity.notFound().build());
        }


        @GetMapping("/users/username/{username}")
        @PreAuthorize("hasRole('ADMIN')")
        public ResponseEntity<User> getUserByUsername(@PathVariable String username) {
            log.info("🔍 Admin fetching user by username: {}", username);
            return userService.getUserByUsername(username)
                    .map(ResponseEntity::ok)
                    .orElse(ResponseEntity.notFound().build());
        }

        @PutMapping("/users/{id}")
        @PreAuthorize("hasRole('ADMIN')")
        public ResponseEntity<User> updateUser(@PathVariable Long id, @RequestBody User user) {
            try {
                log.info("✏️ Admin updating user: {}", id);
                return ResponseEntity.ok(userService.updateUser(id, user));
            } catch (RuntimeException e) {
                log.error("❌ User update failed: {}", e.getMessage());
                return ResponseEntity.notFound().build();
            }
        }


        @DeleteMapping("/users/{id}")
        @PreAuthorize("hasRole('ADMIN')")
        public ResponseEntity<Void> deleteUser(@PathVariable Long id) {
            log.warn("🗑️ Admin deleting user: {}", id);
            userService.deleteUser(id);
            return ResponseEntity.noContent().build();
        }


        private boolean isStrongPassword(String password) {
            boolean hasLetter = password.matches(".*[a-zA-Z].*");
            boolean hasDigit = password.matches(".*\\d.*");
            return password.length() >= 8 && hasLetter && hasDigit;
        }


        @PostMapping("/auth/send-verification-code")
        public ResponseEntity<?> sendVerificationCode(@RequestBody Map<String, String> request) {
            String email = request.get("email");

            try {
                log.info("📧 Envoi du code de vérification à : {}", email);

                // Vérifiez que l'email existe (optionnel)
                if (!userService.existsByEmail(email)) {
                    return ResponseEntity.badRequest()
                            .body(Map.of("error", "Aucun compte associé à cet email"));
                }

                verificationService.sendVerificationCode(email);

                return ResponseEntity.ok(Map.of(
                        "message", "Code de vérification envoyé avec succès"
                ));

            } catch (Exception e) {
                log.error("❌ Erreur : {}", e.getMessage());
                return ResponseEntity.status(500)
                        .body(Map.of("error", "Erreur lors de l'envoi du code"));
            }
        }

        @PostMapping("/auth/verify-code")
        public ResponseEntity<?> verifyCode(@RequestBody Map<String, String> request) {
            String email = request.get("email");
            String code = request.get("code");

            try {
                log.info("🔍 Vérification du code pour : {}", email);

                verificationService.verifyCode(email, code);

                return ResponseEntity.ok(Map.of(
                        "message", "Code vérifié avec succès",
                        "verified", true
                ));

            } catch (RuntimeException e) {
                log.error("❌ Vérification échouée : {}", e.getMessage());
                return ResponseEntity.badRequest()
                        .body(Map.of("error", e.getMessage()));
            }
        }

        @PostMapping("/auth/change-password-after-verification")
        public ResponseEntity<?> changePasswordAfterVerification(@RequestBody Map<String, String> request) {
            String email = request.get("email");
            String newPassword = request.get("newPassword");

            try {
                log.info("🔒 Changement de mot de passe après vérification pour : {}", email);

                // Validation
                if (newPassword == null || newPassword.isBlank()) {
                    return ResponseEntity.badRequest()
                            .body(Map.of("error", "Le mot de passe est requis"));
                }

                if (!isStrongPassword(newPassword)) {
                    return ResponseEntity.badRequest()
                            .body(Map.of("error", "Le mot de passe doit contenir au moins 8 caractères avec lettres et chiffres"));
                }

                // Récupérer l'utilisateur par email
                User user = userService.getUserByEmail(email)
                        .orElseThrow(() -> new RuntimeException("Utilisateur non trouvé"));

                // Changer le mot de passe
                user.setPassword(passwordEncoder.encode(newPassword));
                userService.saveUser(user);

                log.info("✅ Mot de passe changé avec succès pour : {}", email);

                return ResponseEntity.ok(Map.of(
                        "message", "Mot de passe changé avec succès"
                ));

            } catch (Exception e) {
                log.error("❌ Erreur lors du changement de mot de passe : {}", e.getMessage());
                return ResponseEntity.badRequest()
                        .body(Map.of("error", "Erreur lors du changement de mot de passe"));
            }
        }
    }