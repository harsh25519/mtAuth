package bdj.hkb.auth_service.utils;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.MailException;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
@Slf4j
public class EmailService {

    private final JavaMailSender mailSender;

    @Value("${auth.base.url}")
    private String redirectUrl;

    @Async
    public void sendVerificationEmail(String recipientEmail, String token) {

        // Construct the exact URL the Next.js frontend will use to catch the token
        String verificationLink = redirectUrl + "/verify-email?token=" + token;

        SimpleMailMessage message = new SimpleMailMessage();
        message.setTo(recipientEmail);
        message.setSubject("Verify your account");
        message.setText("Welcome! \n\n" +
                "Please click the link below to verify your email address and activate your account:\n\n" +
                verificationLink + "\n\n" +
                "If you did not request this, please ignore this email.");

        try {
            mailSender.send(message);
        } catch (MailException e) {
            log.error("Failed to send verification email: {}", recipientEmail, e.getMessage());
            throw new RuntimeException(e);
        }
    }

    @Async
    public void sendPasswordResetEmail(String email, String token) {
        String resetLink = redirectUrl + "/reset-password?token=" + token;

        SimpleMailMessage message = new SimpleMailMessage();
        message.setTo(email);
        message.setSubject("Password Reset Request");
        message.setText("Hello, \n\n" +
                "You have requested to reset your password. Please click the link below to set a new password:\n\n" +
                resetLink + "\n\n" +
                "If you did not request this, please ignore this email. This link will expire in 15 minutes.");

        try {
            mailSender.send(message);
        } catch (MailException e) {
            log.error("Failed to send password reset mail: {}", email, e.getMessage());
            throw new RuntimeException(e);
        }

    }
}
