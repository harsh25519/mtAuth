package bdj.hkb.auth_service.auth;

import bdj.hkb.auth_service.auth.dto.LocalSignupRequest;
import bdj.hkb.auth_service.client.Client;
import bdj.hkb.auth_service.client.ClientRepository;
import bdj.hkb.auth_service.user.User;
import bdj.hkb.auth_service.user.UserRepository;
import bdj.hkb.auth_service.user.emailVerification.EmailVerificationService;
import bdj.hkb.auth_service.user.emailVerification.dto.ResendVerificationRequest;
import bdj.hkb.auth_service.user.passwordReset.PasswordResetService;
import bdj.hkb.auth_service.user.passwordReset.dto.ForgotPasswordRequest;
import bdj.hkb.auth_service.utils.EmailService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class LocalAuthOrchestrator {

    private final ClientRepository clientRepository;
    private final AuthService authService;
    private final EmailVerificationService emailVerificationService;
    private final EmailService emailService;
    private final UserRepository userRepository;
    private final PasswordResetService passwordResetService;

    // The @Transactional ensures that if the database fails at any point,
    // the whole signup rolls back completely.
    @Transactional
    public void registerUserAndDispatchEmail(LocalSignupRequest request) {

        // 1. Fetch Client
        Client client = clientRepository.findByIdAndIsActiveTrue(request.clientId())
                .orElseThrow(() -> new RuntimeException("Invalid Client ID"));

        // 2. Register User (isActive=false, isEmailVerified=false)
        User savedUser = authService.registerLocalUser(request);

        // 3. Generate Token
        String verificationToken = emailVerificationService.createVerificationToken(savedUser);

        // 4. Dispatch Email (Async)
        emailService.sendVerificationEmail(
                savedUser.getEmail(),
                verificationToken
        );
    }

    @Transactional
    public void resendVerificationEmail(ResendVerificationRequest request) {

        // 1. Fetch Client to get the frontend URL
        Client client = clientRepository.findByIdAndIsActiveTrue(request.clientId())
                .orElseThrow(() -> new RuntimeException("Invalid Client ID"));

        // 2. Fetch the User from this specific tenant
        User user = userRepository.findByClientIdAndEmail(request.clientId(), request.email())
                .orElseThrow(() -> new RuntimeException("User not found"));

        // 3. Prevent spam if they are already verified
        if (user.getIsEmailVerified()) {
            throw new RuntimeException("Email is already verified. Please log in.");
        }

        // 4. Generate a fresh token (This automatically deletes the old one thanks to our @OneToOne logic)
        String newToken = emailVerificationService.createVerificationToken(user);

        // 5. Dispatch the email asynchronously
        emailService.sendVerificationEmail(
                user.getEmail(),
                newToken
        );
    }

    @Transactional
    public void requestPasswordReset(ForgotPasswordRequest request) {
        // 1. Validate Client
        clientRepository.findByIdAndIsActiveTrue(request.clientId())
                .orElseThrow(() -> new RuntimeException("Invalid Client ID"));

        // 2. Locate User and verify local-only origin
        User user = userRepository.findByClientIdAndEmail(request.clientId(), request.email())
                .orElseThrow(() -> new RuntimeException("User not found"));

        if (user.getAuthProvider().equals("local")) {
            String token = passwordResetService.createResetToken(user);
            emailService.sendPasswordResetEmail(user.getEmail(), token);
        }
    }
}