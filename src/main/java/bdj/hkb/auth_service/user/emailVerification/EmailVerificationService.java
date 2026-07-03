package bdj.hkb.auth_service.user.emailVerification;

import bdj.hkb.auth_service.exceptionHandler.InvalidEmailVerificationTokenException;
import bdj.hkb.auth_service.user.User;
import bdj.hkb.auth_service.user.UserRepository;
import bdj.hkb.auth_service.utils.TokenUtils;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.OffsetDateTime;

@Service
@RequiredArgsConstructor
@Slf4j
public class EmailVerificationService {

    private final EmailVerificationTokenRepository tokenRepository;
    private final UserRepository userRepository;

    @Transactional
    public String createVerificationToken(User user) {
        // Enforce the @OneToOne rule: Destroy any existing token for this user
        tokenRepository.deleteByUser(user);

        String token = TokenUtils.generateSecureToken();

        EmailVerificationToken verificationToken = EmailVerificationToken.builder()
                .token(token)
                .user(user)
                .expiresAt(OffsetDateTime.now().plusHours(24)) // 24-hour expiry is standard for email verification
                .build();

        tokenRepository.save(verificationToken);

        log.info(
                "Email verification token generated for user {}",
                user.getId()
        );
        return token;
    }

    @Transactional
    public void verifyEmail(String token) {
        // 1. Find the token
        EmailVerificationToken verificationToken = tokenRepository.findByToken(token)
                .orElseThrow(() -> new InvalidEmailVerificationTokenException("Invalid verification token"));

        // 2. Check Expiration
        if (verificationToken.getExpiresAt().isBefore(OffsetDateTime.now())) {
            log.warn(
                    "Expired email verification token used for user {}",
                    verificationToken.getUser().getId()
            );
            tokenRepository.delete(verificationToken); // Clean up dead tokens
            throw new RuntimeException("Verification token has expired. Please request a new one.");
        }

        // 3. Update the User
        User user = verificationToken.getUser();
        user.setIsEmailVerified(true);
        user.setIsActive(true); // Unlock the account for login!

        userRepository.save(user);

        log.info(
                "Email successfully verified for user {}",
                user.getId()
        );

        // 4. Burn the token to keep the database table razor-thin
        tokenRepository.delete(verificationToken);
    }
}
