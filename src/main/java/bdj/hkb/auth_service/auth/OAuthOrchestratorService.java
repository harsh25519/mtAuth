package bdj.hkb.auth_service.auth;


import bdj.hkb.auth_service.auth.dto.AuthResponse;
import bdj.hkb.auth_service.auth.dto.OAuth2UserInfo;
import bdj.hkb.auth_service.auth.dto.OAuthExchangeRequest;
import bdj.hkb.auth_service.auth.dto.OAuthStateContext;
import bdj.hkb.auth_service.auth.strategy.OAuthProviderStrategy;
import bdj.hkb.auth_service.client.Client;
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
    private final OAuthCodeService codeService;
    private final OAuth2Service oAuth2Service;

    // Spring automatically injects all beans implementing OAuthProviderStrategy into this List
    public OAuthOrchestratorService(
            ClientRepository clientRepository,
            OAuthStateService stateService,
            List<OAuthProviderStrategy> strategies,
            OAuthCodeService codeService, OAuth2Service oAuth2Service) {
        this.clientRepository = clientRepository;
        this.stateService = stateService;
        // Convert the list to a Map for O(1) instant lookups
        this.strategyMap = strategies.stream()
                .collect(Collectors.toMap(OAuthProviderStrategy::getProvider, Function.identity()));
        this.codeService = codeService;
        this.oAuth2Service = oAuth2Service;
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

    // Make sure to inject OAuthCodeService and OAuth2Service into the constructor!

    public String handleProviderCallback(OAuthProvider provider, String providerCode, String state) {
        OAuthStateContext stateContext = stateService.validateAndConsumeState(state);
        if (stateContext.provider() != provider) throw new RuntimeException("OAuth provider mismatch");

        Client client = clientRepository.findByIdAndIsActiveTrue(stateContext.clientId())
                .orElseThrow(() -> new RuntimeException("Invalid Client ID"));

        OAuthProviderStrategy strategy = strategyMap.get(provider);
        OAuth2UserInfo userInfo = strategy.fetchUserInfo(providerCode);

        AuthResponse authResponse = oAuth2Service.processOAuthUser(client, userInfo, provider);

        // Lock the JWTs in Redis for 30 seconds
        String authCode = codeService.saveAuthResponse(authResponse);

        // Construct the frontend redirect URL
        return client.getFrontendUrl() + "/oauth/callback?code=" + authCode;
    }

    // 2. NEW: Exchange the code for the tokens
    public AuthResponse exchangeCodeForTokens(OAuthExchangeRequest request) {
        Client client = clientRepository.findByIdAndIsActiveTrue(request.clientId())
                .orElseThrow(() -> new RuntimeException("Invalid Client ID"));

        // Verify the client secret (use passwordEncoder.matches if hashed)
        if (!client.getClientSecret().equals(request.clientSecret())) {
            throw new RuntimeException("Invalid client secret");
        }

        // Unlock the Redis Locker (burns the code instantly)
        return codeService.consumeAuthCode(request.code());
    }
}