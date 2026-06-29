package bdj.hkb.auth_service.utils;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
@Slf4j
public class EmailService {

    private final JavaMailSender mailSender;

    @Async
    public void sendVerificationEmail(String recipientEmail, String token, String redirectUrl) {

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
        } catch (Exception e) {
            log.error("Failed to send email to {}: {}", recipientEmail, e.getMessage());
        }
    }
}
