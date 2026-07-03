package bdj.hkb.auth_service.user.passwordReset;

import bdj.hkb.auth_service.exceptionHandler.InvalidPasswordResetTokenException;
import bdj.hkb.auth_service.user.User;
import bdj.hkb.auth_service.user.UserRepository;
import bdj.hkb.auth_service.utils.TokenUtils;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.OffsetDateTime;

@Service
@RequiredArgsConstructor
@Slf4j
public class PasswordResetService {

    private final PasswordResetTokenRepository tokenRepository;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    @Transactional
    public String createResetToken(User user) {
        // Clear any old, unused reset tokens for this user
        tokenRepository.deleteByUser(user);

        String token = TokenUtils.generateSecureToken();

        PasswordResetToken resetToken = PasswordResetToken.builder()
                .token(token)
                .user(user)
                .expiresAt(OffsetDateTime.now().plusMinutes(15)) // 15-minute expiry for security
                .build();

        tokenRepository.save(resetToken);

        log.info(
                "Password reset token generated for user {}",
                user.getId()
        );

        return token;
    }

    @Transactional
    public void executePasswordReset(String token, String newRawPassword) {
        // 1. Find the token
        PasswordResetToken resetToken = tokenRepository.findByToken(token)
                .orElseThrow(() -> new InvalidPasswordResetTokenException("Invalid password reset token"));

        // 2. Check Expiration
        if (resetToken.getExpiresAt().isBefore(OffsetDateTime.now())) {
            log.warn(
                    "Expired password reset token used for user {}",
                    resetToken.getUser().getId()
            );

            tokenRepository.delete(resetToken);
            throw new RuntimeException("Reset token has expired. Please request a new one.");
        }

        // 3. Hash and update the password
        User user = resetToken.getUser();
        user.setPasswordHash(passwordEncoder.encode(newRawPassword));
        userRepository.save(user);

        // 4. Burn the token so it cannot be used twice
        tokenRepository.delete(resetToken);

        log.info(
                "Password successfully reset for user {}",
                user.getId()
        );

    }
}
