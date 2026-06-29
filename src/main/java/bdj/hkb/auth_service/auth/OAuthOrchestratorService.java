package bdj.hkb.auth_service.auth;


import bdj.hkb.auth_service.auth.strategy.OAuthProviderStrategy;
import bdj.hkb.auth_service.client.ClientRepository;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.function.Function;
import java.util.stream.Collectors;

@Service
public class OAuthOrchestratorService {

    private final ClientRepository clientRepository;
    private final OAuthStateService stateService;
    private final Map<OAuthProvider, OAuthProviderStrategy> strategyMap;

    // Spring automatically injects all beans implementing OAuthProviderStrategy into this List
    public OAuthOrchestratorService(
            ClientRepository clientRepository,
            OAuthStateService stateService,
            List<OAuthProviderStrategy> strategies) {
        this.clientRepository = clientRepository;
        this.stateService = stateService;
        // Convert the list to a Map for O(1) instant lookups
        this.strategyMap = strategies.stream()
                .collect(Collectors.toMap(OAuthProviderStrategy::getProvider, Function.identity()));
    }

    public String getAuthorizationUrl(OAuthProvider provider, UUID clientId) {
        // 1. Validate Client
        clientRepository.findByIdAndIsActiveTrue(clientId)
                .orElseThrow(() -> new RuntimeException("Invalid or inactive Client ID"));

        // 2. Generate State (now includes the provider for security!)
        String state = stateService.generateAndSaveState(clientId, provider);

        // 3. Delegate to the specific provider strategy
        OAuthProviderStrategy strategy = strategyMap.get(provider);
        if (strategy == null) {
            throw new IllegalArgumentException("No strategy configured for provider: " + provider);
        }

        return strategy.buildAuthorizationUrl(state);
    }
}