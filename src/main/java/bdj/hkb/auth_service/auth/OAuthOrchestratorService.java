package bdj.hkb.auth_service.auth;


import bdj.hkb.auth_service.auth.dto.AuthResponse;
import bdj.hkb.auth_service.auth.dto.OAuth2UserInfo;
import bdj.hkb.auth_service.auth.dto.OAuthExchangeRequest;
import bdj.hkb.auth_service.auth.dto.OAuthStateContext;
import bdj.hkb.auth_service.auth.strategy.OAuthProviderStrategy;
import bdj.hkb.auth_service.client.Client;
import bdj.hkb.auth_service.client.ClientRepository;
import bdj.hkb.auth_service.exceptionHandler.ClientNotFoundException;
import bdj.hkb.auth_service.exceptionHandler.InvalidClientSecretException;
import bdj.hkb.auth_service.exceptionHandler.InvalidOAuthProviderException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.function.Function;
import java.util.stream.Collectors;

@Service
@Slf4j
public class OAuthOrchestratorService {

    private final ClientRepository clientRepository;
    private final OAuthStateService stateService;
    private final Map<OAuthProvider, OAuthProviderStrategy> strategyMap;
    private final OAuthCodeService codeService;
    private final OAuth2Service oAuth2Service;
    private final PasswordEncoder passwordEncoder;

    // Spring automatically injects all beans implementing OAuthProviderStrategy into this List
    @Autowired
    public OAuthOrchestratorService(
            ClientRepository clientRepository,
            OAuthStateService stateService,
            List<OAuthProviderStrategy> strategies,
            OAuthCodeService codeService, OAuth2Service oAuth2Service, PasswordEncoder passwordEncoder) {
        this.clientRepository = clientRepository;
        this.stateService = stateService;
        // Convert the list to a Map for O(1) instant lookups
        this.strategyMap = strategies.stream()
                .collect(Collectors.toMap(OAuthProviderStrategy::getProvider, Function.identity()));
        this.codeService = codeService;
        this.oAuth2Service = oAuth2Service;
        this.passwordEncoder = passwordEncoder;
    }

    public String getAuthorizationUrl(OAuthProvider provider, UUID clientId) {

        log.info(
                "OAuth authorization requested for provider {} under client {}",
                provider,
                clientId
        );

        // 1. Validate Client
        clientRepository.findByIdAndIsActiveTrue(clientId)
                .orElseThrow(() -> new ClientNotFoundException("Invalid or inactive Client ID"));

        // 2. Generate State (now includes the provider for security!)
        String state = stateService.generateAndSaveState(clientId, provider);

        // 3. Delegate to the specific provider strategy
        OAuthProviderStrategy strategy = strategyMap.get(provider);
        if (strategy == null) {
            throw new IllegalArgumentException("No strategy configured for provider: " + provider);
        }

        String authUrl = strategy.buildAuthorizationUrl(state);;
        log.info(
                "Generated OAuth authorization URL for provider {} under client {}",
                provider,
                clientId
        );

        return authUrl;
    }

    // Make sure to inject OAuthCodeService and OAuth2Service into the constructor!

    public String handleProviderCallback(OAuthProvider provider, String providerCode, String state) {
        log.info(
                "Received OAuth callback for provider {}",
                provider
        );

        OAuthStateContext stateContext = stateService.validateAndConsumeState(state);
        if (stateContext.provider() != provider){
            throw new InvalidOAuthProviderException("OAuth provider mismatch");
        }

        log.info(
                "OAuth state validated for provider {} and client {}",
                provider,
                stateContext.clientId()
        );

        Client client = clientRepository.findByIdAndIsActiveTrue(stateContext.clientId())
                .orElseThrow(() -> new ClientNotFoundException("Invalid Client ID"));

        OAuthProviderStrategy strategy = strategyMap.get(provider);
        OAuth2UserInfo userInfo = strategy.fetchUserInfo(providerCode);

        AuthResponse authResponse = oAuth2Service.processOAuthUser(client, userInfo, provider);

        log.info(
                "OAuth provider {} authenticated user {}",
                provider,
                userInfo.email()
        );

        // Lock the JWTs in Redis for 30 seconds
        String authCode = codeService.saveAuthResponse(authResponse);

        log.info(
                "Generated OAuth bridge code for provider {} and client {}",
                provider,
                client.getId()
        );

        // Construct the frontend redirect URL
        return client.getRedirectUrl() + "/oauth/callback?code=" + authCode;
    }

    // 2. Exchange the code for the tokens
    public AuthResponse exchangeCodeForTokens(OAuthExchangeRequest request) {

        log.info(
                "OAuth token exchange requested for client {}",
                request.clientId()
        );

        Client client = clientRepository.findByIdAndIsActiveTrue(request.clientId())
                .orElseThrow(() -> new RuntimeException("Invalid Client ID"));

        // Verify the client secret (use passwordEncoder.matches if hashed)
        if (!passwordEncoder.matches(request.clientSecret(), client.getClientSecret())) {
            throw new InvalidClientSecretException("Invalid client secret");
        }

        AuthResponse response = codeService.consumeAuthCode(request.code());

        log.info(
                "OAuth token exchange completed for client {}",
                request.clientId()
        );

        // Unlock the Redis Locker (burns the code instantly)
        return response;
    }
}