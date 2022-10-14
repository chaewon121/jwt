package com.example.jwt.config;



import com.example.jwt.config.jwt.JwtAuthenticationFilter;
import com.example.jwt.config.jwt.JwtAuthorizationFilter;
import com.example.jwt.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@Configuration
@EnableWebSecurity // 시큐리티 활성화 -> 기본 스프링 필터체인에 등록
@RequiredArgsConstructor
public class SecurityConfig extends WebSecurityConfigurerAdapter{

	private final UserRepository userRepository;

	private final CorsConfig corsConfig;
	@Bean
	public BCryptPasswordEncoder passwordEncoder(){
		return new BCryptPasswordEncoder();
	}
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http
				//내 서버는 cors에서 다 허용될거임
				.addFilter(corsConfig.corsFilter())
				.csrf().disable()
				//세션 안쓸거임
				.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)

				.and()
				.formLogin().disable()
				.httpBasic().disable() //기본인증방식 안씀-> 헤더에 토큰담아서(jwt)
				//필터걸어줌줌
				.addFilter(new JwtAuthenticationFilter(authenticationManager()))
				.addFilter(new JwtAuthorizationFilter(authenticationManager(), userRepository))

				.authorizeRequests()
				.antMatchers("/api/v1/user/**")
				.access("hasRole('ROLE_USER') or hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
				.antMatchers("/api/v1/manager/**")
					.access("hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
				.antMatchers("/api/v1/admin/**")
					.access("hasRole('ROLE_ADMIN')")

				.antMatchers("/h2-console/**")
				.permitAll()

				.anyRequest().permitAll();
	}
}






