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
    private final VerificationService verificationService;

    // ============================
    //  🔐 AUTHENTICATION
    // ============================

    @PostMapping("/auth/register")
    public ResponseEntity<?> register(@RequestBody User user) {
        try {
            log.info("📝 Registration attempt: {}", user.getEmail());

            // Validation email
            if (user.getEmail() == null || user.getEmail().isBlank()) {
                return bad("Email is required");
            }

            // Validation password
            if (user.getPassword() == null || user.getPassword().isBlank()) {
                return bad("Password is required");
            }

            if (!isStrongPassword(user.getPassword())) {
                return bad("Password must be at least 8 characters with letters and digits");
            }

            if (userService.existsByUsername(user.getUsername()))
                return bad("Username already exists");

            if (userService.existsByEmail(user.getEmail()))
                return bad("Email already exists");

            user.setPassword(passwordEncoder.encode(user.getPassword()));
            User savedUser = userService.saveUser(user);

            String token = jwtService.generateToken(savedUser);

            return ok(
                    "token", token,
                    "username", savedUser.getUsername(),
                    "email", savedUser.getEmail(),
                    "role", savedUser.getRole()
            );

        } catch (Exception e) {
            log.error("❌ Registration failed: {}", e.getMessage());
            return bad("Registration failed: " + e.getMessage());
        }
    }

    @PostMapping("/auth/login")
    public ResponseEntity<?> login(@RequestBody Map<String, String> loginRequest) {
        String login = loginRequest.get("username");
        String password = loginRequest.get("password");

        try {
            log.info("🔐 Login attempt: {}", login);

            if (loginAttemptService.isBlocked(login))
                return tooMany("Too many failed attempts. Try again later.");

            String usernameToAuth = userService.getUserByEmail(login)
                    .map(User::getUsername)
                    .orElse(login);

            Authentication auth = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(usernameToAuth, password)
            );

            User user = userService.getUserByUsername(usernameToAuth)
                    .orElseThrow(() -> new RuntimeException("User not found"));

            loginAttemptService.loginSucceeded(login);

            String token = jwtService.generateToken(user);

            return ok(
                    "token", token,
                    "username", user.getUsername(),
                    "email", user.getEmail(),
                    "role", user.getRole()
            );

        } catch (Exception e) {
            loginAttemptService.loginFailed(login);
            log.warn("❌ Login failed: {}", e.getMessage());
            return unauthorized("Invalid username or password.");
        }
    }

    // ============================
    // 🔒 PASSWORD RESET
    // ============================

    @PostMapping("/auth/forgot-password")
    public ResponseEntity<?> forgotPassword(@RequestBody Map<String, String> request) {
        String email = request.get("email");
        try {
            log.info("🔑 Password reset requested: {}", email);
            passwordResetService.initiatePasswordReset(email);

            return ok("message", "If this email exists, a reset link has been sent.");
        } catch (Exception e) {
            log.error("❌ Error: {}", e.getMessage());
            return ok("message", "If this email exists, a reset link has been sent.");
        }
    }

    @PostMapping("/auth/reset-password")
    public ResponseEntity<?> resetPassword(@RequestBody Map<String, String> request) {
        try {
            String token = request.get("token");
            String newPassword = request.get("newPassword");

            if (newPassword == null || newPassword.isBlank())
                return bad("Password is required");

            if (!isStrongPassword(newPassword))
                return bad("Password must contain letters and digits, min 8 chars");

            passwordResetService.resetPassword(token, newPassword);

            return ok("message", "Password reset successfully");

        } catch (Exception e) {
            return bad(e.getMessage());
        }
    }

    // ============================
    // 📧 EMAIL VERIFICATION
    // ============================

    @PostMapping("/auth/send-verification-code")
    public ResponseEntity<?> sendVerificationCode(@RequestBody Map<String, String> req) {
        String email = req.get("email");

        if (!userService.existsByEmail(email))
            return bad("No account found with this email");

        verificationService.sendVerificationCode(email);
        return ok("message", "Verification code sent");
    }

    @PostMapping("/auth/verify-code")
    public ResponseEntity<?> verifyCode(@RequestBody Map<String, String> req) {
        try {
            verificationService.verifyCode(req.get("email"), req.get("code"));
            return ok("verified", true);
        } catch (RuntimeException e) {
            return bad(e.getMessage());
        }
    }

    @PostMapping("/auth/change-password-after-verification")
    public ResponseEntity<?> changePasswordAfterVerification(@RequestBody Map<String, String> req) {
        try {
            String email = req.get("email");
            String newPassword = req.get("newPassword");

            if (!isStrongPassword(newPassword))
                return bad("Password too weak");

            User user = userService.getUserByEmail(email)
                    .orElseThrow(() -> new RuntimeException("User not found"));

            user.setPassword(passwordEncoder.encode(newPassword));
            userService.saveUser(user);

            return ok("message", "Password changed successfully");

        } catch (Exception e) {
            return bad(e.getMessage());
        }
    }

    // ============================
    // 👤 USER MANAGEMENT (ADMIN)
    // ============================

    @GetMapping("/users")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<List<User>> getAllUsers() {
        return ResponseEntity.ok(userService.getAllUsers());
    }

    @PostMapping("/users")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<User> saveUser(@RequestBody User user) {
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        return ResponseEntity.ok(userService.saveUser(user));
    }

    @PutMapping("/users/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<?> updateUser(@PathVariable Long id, @RequestBody User user) {
        try {
            return ResponseEntity.ok(userService.updateUser(id, user));
        } catch (Exception e) {
            return notFound("User not found");
        }
    }

    @DeleteMapping("/users/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<?> deleteUser(@PathVariable Long id) {
        userService.deleteUser(id);
        return ResponseEntity.noContent().build();
    }

    // ============================
    // 🔧 UTILITIES
    // ============================

    private boolean isStrongPassword(String password) {
        return password.length() >= 8 &&
                password.matches(".*[a-zA-Z].*") &&
                password.matches(".*\\d.*");
    }

    private ResponseEntity<?> bad(String msg) {
        return ResponseEntity.badRequest().body(Map.of("error", msg));
    }

    private ResponseEntity<?> unauthorized(String msg) {
        return ResponseEntity.status(401).body(Map.of("error", msg));
    }

    private ResponseEntity<?> tooMany(String msg) {
        return ResponseEntity.status(429).body(Map.of("error", msg));
    }

    private ResponseEntity<?> notFound(String msg) {
        return ResponseEntity.status(404).body(Map.of("error", msg));
    }

    private ResponseEntity<?> ok(Object... args) {
        Map<String, Object> map = new HashMap<>();
        for (int i = 0; i < args.length; i += 2)
            map.put(args[i].toString(), args[i + 1]);
        return ResponseEntity.ok(map);
    }
}
