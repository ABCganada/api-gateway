package com.service.apigateway.filter;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpCookie;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.Date;
import java.util.List;

@Slf4j
@Component
public class AuthorizationHeaderFilter extends AbstractGatewayFilterFactory<AuthorizationHeaderFilter.Config> {

    @Value("${jwt.secretKey}")
    private String secretKey;

    private final static Logger logger = LoggerFactory.getLogger(AuthorizationHeaderFilter.class);
    private String loginUrl = "http://localhost:8081/auth/login";

    public AuthorizationHeaderFilter() {
        super(Config.class);
    }

    @Override
    public GatewayFilter apply(AuthorizationHeaderFilter.Config config) {
        return (exchange, chain) -> {
            String requiredRole = config.getRequiredRole();
            ServerHttpRequest request = exchange.getRequest();
            logger.info("요청한 uri : "+request.getURI());

            if (request.getURI().getPath().equals(loginUrl)) {
                return chain.filter(exchange);
            }

            //쿠키에서 jwt token 확인
            List<HttpCookie> cookies = request.getCookies().get("jwtToken");
//            String token = request.getCookies().get("jwtToken").toString();
            if (cookies == null || cookies.isEmpty()) {
                return redirectToLogin(exchange);
            }

            String token = cookies.get(0).getValue();
//            token = token.substring(10);

            if (!isJwtValid(token)) {
                return onError(exchange, "JWT token is not valid", HttpStatus.UNAUTHORIZED);
            }

            //사용자 id 추출
            String userId = resolveTokenUserId(token);
            ServerHttpResponse response = exchange.getResponse();
            response.addCookie(ResponseCookie.from("userId", userId).path("/").build());


            return chain.filter(exchange);

        };
    }

    private Mono<Void> onError(ServerWebExchange exchange, String err, HttpStatus httpStatus) {
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(httpStatus);
        logger.error(err);
        return response.setComplete();
    }

    private String resolveTokenRole(String token){
        try {
            String subject = Jwts.parser().setSigningKey(secretKey).parseClaimsJws(token).getBody().get("roles").toString();
            return subject;
        }catch (Exception e){
            logger.info("유저 권한 체크 실패");
            return "e";
        }
    }

    private String resolveTokenUserId(String token){
        try {
            String userId = Jwts.parser().setSigningKey(secretKey).parseClaimsJws(token).getBody().get("id").toString();
            return userId;
        }catch (Exception e){
            logger.info("유저 권한 체크 실패");
            return null;
        }
    }

    private Mono<Void> redirectToLogin(ServerWebExchange exchange) {
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(HttpStatus.SEE_OTHER);
        response.getHeaders().set(HttpHeaders.LOCATION, loginUrl);

        return response.setComplete();
    }

    private boolean isJwtValid(String token) {
        logger.info("[JwtTokenProvider] validateToken, 토큰 유효성 체크");
        try{
            Jws<Claims> claims = Jwts.parser().setSigningKey(secretKey).parseClaimsJws(token);
            return !claims.getBody().getExpiration().before(new Date());
        } catch (Exception e){
            e.printStackTrace();
            logger.info("[JwtTokenProvider] validateToken, 토큰 유효성 체크 예외 발생");
            return false;
        }
    }

    public static class Config {
        private String requiredRole;

        public String getRequiredRole() {
            return requiredRole;
        }

        public void setRequiredRole(String requiredRole) {
            this.requiredRole = requiredRole;
        }
    }
}
