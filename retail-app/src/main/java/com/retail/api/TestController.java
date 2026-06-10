package com.retail.api;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import java.time.LocalDateTime;
import java.util.Map;

@RestController
public class TestController {

    @GetMapping("/status")
    public Map<String, Object> getStatus() {
        return Map.of(
                "status", "UP Привіт Крокодилам",
                "message", "Retail Core для Белівера працює на AWS",
                "timestamp", LocalDateTime.now(),
                "architecture", "Modular Monolith (Java 21 + Boot)"
        );
    }
}