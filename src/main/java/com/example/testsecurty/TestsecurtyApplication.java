package com.example.testsecurty;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.ComponentScan;

@SpringBootApplication
@ComponentScan(basePackages = {
        "com.example.testsecurty.config",
        "com.example.testsecurty.security",
        "com.example.testsecurty.Controller",
        "com.example.testsecurty.Services",
        "com.example.testsecurty.dao"
})
public class TestsecurtyApplication {

    public static void main(String[] args) {
        SpringApplication.run(TestsecurtyApplication.class, args);
    }
}