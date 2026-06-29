package bdj.hkb.auth_service.client;

import bdj.hkb.auth_service.client.dto.ClientResponse;
import bdj.hkb.auth_service.client.dto.RegisterClientRequest;
import bdj.hkb.auth_service.client.dto.RegisterClientResponse;
import bdj.hkb.auth_service.exceptionHandler.ClientNotFoundException;
import bdj.hkb.auth_service.exceptionHandler.UserNotFoundException;
import bdj.hkb.auth_service.role.UserRole;
import bdj.hkb.auth_service.role.UserRoleRepository;
import bdj.hkb.auth_service.security.JwtUtilService;
import bdj.hkb.auth_service.user.User;
import bdj.hkb.auth_service.user.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.SecureRandom;
import java.util.Base64;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class ClientService {

    private final ClientRepository clientRepository;
    private final PasswordEncoder passwordEncoder;

    private static final SecureRandom RANDOM = new SecureRandom();
    private final JwtUtilService jwtUtilService;
    private final UserRepository userRepository;
    private final UserRoleRepository userRoleRepository;

    // Inject the Master ID from application.yml
    @Value("${platform.master-client-id}")
    private String masterClientId;

    @Transactional
    public RegisterClientResponse registerClient(RegisterClientRequest request, String token){

        String tokenClientId = jwtUtilService.extractClientId(token);
        String userId = jwtUtilService.extractUserId(token);

        // --- THE MASTER TENANT CHECK ---
        if (!masterClientId.equals(tokenClientId)) {
            throw new AccessDeniedException("Unauthorized: Only users belonging to the main platform can create new clients.");
        }

        // 1. Generate a cryptographically secure raw secret
        String rawSecret = generateSecret();

        // 2. Hash the secret for safe database storage
        String hashedSecret = passwordEncoder.encode(rawSecret);

        // 3. Build and save the new Client (Tenant) entity
        Client newClient = Client.builder()
                .name(request.name())
                .clientSecret(hashedSecret)
                .isActive(true)
                .redirectUrl(request.redirectUrl())
                .build();

        Client savedClient = clientRepository.saveAndFlush(newClient);


        User sourceUser = userRepository.findById(UUID.fromString(userId))
                .orElseThrow(() -> new UserNotFoundException("Requester not found"));

        User adminUser ;
        if(sourceUser.getAuthProvider().equals("local")){
            adminUser = User.builder()
                    .email(sourceUser.getEmail())
                    .passwordHash(sourceUser.getPasswordHash())
                    .client(savedClient)
                    .authProvider("local")
                    .isEmailVerified(true)
                    .isActive(true)
                    .build();
        }else{
            adminUser = User.builder()
                    .email(sourceUser.getEmail())
                    .authProvider(sourceUser.getAuthProvider())
                    .client(savedClient)
                    .providerId(sourceUser.getProviderId())
                    .isEmailVerified(true)
                    .isActive(true)
                    .build();
        }


        userRepository.save(adminUser);

        UserRole adminRole = UserRole.builder()
                .user(adminUser)
                .client(savedClient)
                .role("ROLE_ADMIN")
                .build();

        userRoleRepository.save(adminRole);

        // 4. Return the raw secret to the user
        return new RegisterClientResponse(
                savedClient.getName(),
                savedClient.getId(),
                rawSecret,
                "Warning: Copy this clientSecret immediately. You will not be able to see it again."
        );
    }

    public Page<ClientResponse> getAllClients(Pageable pageable) {
        return clientRepository.findAll(pageable)
                .map(c -> new ClientResponse(
                        c.getId(),
                        c.getName(),
                        c.getIsActive(),
                        c.getCreatedAt()));
    }

    public ClientResponse getActiveClientById(UUID clientId) {
        return clientRepository.findByIdAndIsActiveTrue(clientId)
                .map(c -> new ClientResponse(
                        c.getId(),
                        c.getName(),
                        c.getIsActive(),
                        c.getCreatedAt()
                ))
                .orElseThrow(() -> new ClientNotFoundException("Invalid client"));
    }

    @Transactional
    public void updateRedirectUrl(String token, String newUrl) {
        String jwt = token.replace("Bearer ", "");

        String tokenClientId = jwtUtilService.extractClientId(jwt);

        Client targetClient = clientRepository.findById(UUID.fromString(tokenClientId))
                .orElseThrow(() -> new RuntimeException("Client not found"));

        targetClient.setRedirectUrl(newUrl);
        clientRepository.save(targetClient);
    }
    private String generateSecret() {
        byte[] bytes = new byte[32]; // 256 bits
        RANDOM.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}
