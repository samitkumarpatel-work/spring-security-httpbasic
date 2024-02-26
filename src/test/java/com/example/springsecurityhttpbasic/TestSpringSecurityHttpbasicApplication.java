package com.example.springsecurityhttpbasic;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.context.annotation.Bean;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.utility.DockerImageName;

@TestConfiguration(proxyBeanMethods = false)
public class TestSpringSecurityHttpbasicApplication {

	@Bean
	@ServiceConnection
	PostgreSQLContainer<?> postgresContainer() {
		return new PostgreSQLContainer<>(DockerImageName.parse("postgres:latest"))
				.withInitScript("db/schema.sql")
				.waitingFor(Wait.forListeningPort());
	}

	public static void main(String[] args) {
		SpringApplication.from(SpringSecurityHttpbasicApplication::main).with(TestSpringSecurityHttpbasicApplication.class).run(args);
	}

}
