package com.example.jwt.config.auth;

import java.util.ArrayList;
import java.util.Collection;

import com.example.jwt.model.UserEntity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

public class PrincipalDetails implements UserDetails{

	private UserEntity user;

    public PrincipalDetails(UserEntity user){
        this.user = user;
    }

    public UserEntity getUser() {
		return user;
	}

    @Override
    public String getPassword() {
        return user.getPassword();
    }

    @Override
    public String getUsername() {
        return user.getUsername();
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }
    
	@Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
		Collection<GrantedAuthority> authorities = new ArrayList<GrantedAuthority>();
        user.getRoleList().forEach(r -> {
        	authorities.add(()->{ return r;});
        });
        return authorities;
    }
}
