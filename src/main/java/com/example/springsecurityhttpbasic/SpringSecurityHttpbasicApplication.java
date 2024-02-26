package com.example.springsecurityhttpbasic;

import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.annotation.Id;
import org.springframework.data.relational.core.mapping.Table;
import org.springframework.data.repository.ListCrudRepository;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.stereotype.Service;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.time.LocalDate;
import java.util.Collection;
import java.util.Map;

@SpringBootApplication
public class SpringSecurityHttpbasicApplication {

	public static void main(String[] args) {
		SpringApplication.run(SpringSecurityHttpbasicApplication.class, args);
	}
}

record Message(String message, LocalDate date) {}
@Table("users")
record User(@Id Integer id, String username, String password) implements UserDetails {
	@Override
	public Collection<? extends GrantedAuthority> getAuthorities() {
		return null;
	}

	@Override
	public String getPassword() {
		return password;
	}

	@Override
	public String getUsername() {
		return username;
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
}

interface UserRepository extends ListCrudRepository<User, Integer> {
	User findByUsername(String username);
}

@Service
@RequiredArgsConstructor
@Slf4j
class UserService implements UserDetailsService {
	final UserRepository userRepository;
	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		var userDetails = userRepository.findByUsername(username);
		log.info("db info for user : {} is {}", username, userDetails);
		return userDetails;
	}
}

@RestController
@RequiredArgsConstructor
@Slf4j
class ApplicationRouters {
	final BCryptPasswordEncoder bCryptPasswordEncoder;
	final UserRepository userRepository;

	@GetMapping("/message")
	Map<String, String> get() {
		return Map.of("message", "Hello, World!");
	}

	@PostMapping("/message")
	Message post(@RequestBody Message message) {
		return message;
	}

	@PostMapping("/register")
	@Validated
	Map<String, String> register(@RequestBody User user) {
		try {
			userRepository.save(new User(null, user.username(), bCryptPasswordEncoder.encode(user.password())));
			return Map.of("message", "Register Successfully!");
		} catch (Exception e) {
			log.error("ERROR",e);
			throw new RuntimeException("Username is already taken!");
		}
	}
}

@Configuration
@EnableWebSecurity
class SecurityConfiguration {

	@Bean
	BCryptPasswordEncoder bCryptPasswordEncoder() {
		return new BCryptPasswordEncoder();
	}

	@Bean
	@SneakyThrows
	public SecurityFilterChain securityFilterChain(HttpSecurity http) {
		http
				.authorizeHttpRequests((authorize) -> authorize
						.requestMatchers(HttpMethod.POST, "/register").permitAll()
						.requestMatchers("/error").permitAll()
						.anyRequest().authenticated()
				)
				//csrf should not be Disable for controller routes
				.csrf((csrf) -> csrf.disable())
				.sessionManagement((session) -> session
						.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
				)
				.httpBasic(Customizer.withDefaults());
		return http.build();
	}
}
