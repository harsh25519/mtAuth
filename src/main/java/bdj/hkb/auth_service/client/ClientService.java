package bdj.hkb.auth_service.client;

import bdj.hkb.auth_service.client.dto.ClientResponse;
import bdj.hkb.auth_service.client.dto.RegisterClientRequest;
import bdj.hkb.auth_service.client.dto.RegisterClientResponse;
import bdj.hkb.auth_service.exceptionHandler.ClientNotFoundException;
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

    // Inject the Master ID from application.yml
    @Value("${platform.master-client-id}")
    private String masterClientId;

    @Transactional
    public RegisterClientResponse registerClient(RegisterClientRequest request, String tokenClientId){

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
                .build();

        Client savedClient = clientRepository.save(newClient);

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

    private String generateSecret() {
        byte[] bytes = new byte[32]; // 256 bits
        RANDOM.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}
