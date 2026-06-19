package bdj.hkb.auth_service.security;

import bdj.hkb.auth_service.user.User;
import org.jspecify.annotations.Nullable;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

public class CustomUserDetails implements UserDetails {

    private final User user;
    private final Collection<? extends GrantedAuthority> authorities;

    public CustomUserDetails(User user, List<String> roles) {
        this.user = user;
        this.authorities = roles.stream()
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());;
    }

    public UUID getUserId() {
        return user.getId();
    }

    public UUID getClientId() {
        return user.getClient().getId();
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities;
    }

    @Override
    public @Nullable String getPassword() {
        return user.getPasswordHash() != null ? user.getPasswordHash() : "";
    }

    @Override
    public String getUsername() {
        return user.getId().toString();
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return user.getIsActive();
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return user.getIsActive();
    }
}
