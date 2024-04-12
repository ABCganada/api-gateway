package com.service.apigateway.controller;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpCookie;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@Controller
public class ApiGatewayController {

    @Value("${jwt.secretKey}")
    private String secretKey;

    @GetMapping("/main")
    public Mono<String> main(Model model, ServerWebExchange exchange) {
        boolean isLoggedIn = extractJwtToken(exchange);
        model.addAttribute("isLoggedIn", isLoggedIn);
        return Mono.just("main");
    }

    private boolean extractJwtToken(ServerWebExchange exchange) {
        HttpCookie token = exchange.getRequest().getCookies().getFirst("jwtToken");
        return token != null && !token.getValue().isEmpty();
    }
}
