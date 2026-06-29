package bdj.hkb.auth_service.config;

import bdj.hkb.auth_service.client.Client;
import bdj.hkb.auth_service.client.ClientRepository;
import bdj.hkb.auth_service.role.UserRole;
import bdj.hkb.auth_service.role.UserRoleRepository;
import bdj.hkb.auth_service.user.User;
import bdj.hkb.auth_service.user.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.UUID;

@Slf4j
@Component
@RequiredArgsConstructor
public class AdminSeeder implements ApplicationRunner {

    private final ClientRepository clientRepository;
    private final UserRepository userRepository;
    private final UserRoleRepository userRoleRepository;
    private final PasswordEncoder passwordEncoder;

    @Value("${platform.master-client-id}")
    private String consoleClientId;

    @Value("${platform.admin-email}")
    private String adminEmail;

    @Value("${platform.admin-password}")
    private String adminPassword;

    @Override
    public void run(ApplicationArguments args) {
        UUID clientUuid = UUID.fromString(consoleClientId);

        // seed console client if not exists
        Client client = clientRepository.findById(clientUuid)
                .orElseGet(() -> {
                    log.info("Seeding Master Console Client...");
                    return clientRepository.saveAndFlush(Client.builder()
                            .id(clientUuid)
                            .name("auth-console")
                            .clientSecret(passwordEncoder.encode("secret123"))
                            .isActive(true)
                            .build());
                });

        // seed admin user if not exists
        if (!userRepository.existsByClientIdAndEmail(clientUuid, adminEmail)) {
            log.info("Seeding Initial Platform Admin: {}", adminEmail);
            User admin = userRepository.save(User.builder()
                    .client(client)
                    .email(adminEmail)
                    .passwordHash(passwordEncoder.encode(adminPassword))
                    .authProvider("local")
                    .isActive(true)
                    .build());

            userRoleRepository.save(UserRole.builder()
                    .user(admin)
                    .client(client)
                    .role("ROLE_AUTH_ADMIN")
                    .build());
        }else{
            log.info("Platform Admin already exists. Skipping seeding.");
        }
    }
}
