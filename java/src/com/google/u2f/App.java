package com.google.u2f;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.SecurityAutoConfiguration;
import org.springframework.core.env.ConfigurableEnvironment;

@SpringBootApplication(exclude = SecurityAutoConfiguration.class) 
public class App {

    @Autowired
    ConfigurableEnvironment env;
		
    public static void main(String[] args) {
        SpringApplication.run(App.class, args);
    }
	
}
