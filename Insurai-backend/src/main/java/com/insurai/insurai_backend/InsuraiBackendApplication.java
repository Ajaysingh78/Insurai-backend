package com.insurai.insurai_backend;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@SpringBootApplication
@EnableScheduling
public class InsuraiBackendApplication {

	public static void main(String[] args) {
		SpringApplication.run(InsuraiBackendApplication.class, args);
	}
}

@RestController
class HelloController {

	@GetMapping("/hello")
	public String hello() {
		return "Hello World from InsurAI!";
	}
}