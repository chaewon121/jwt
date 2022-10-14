package com.example.jwt.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;

@Configuration
public class CorsConfig {

    @Bean
    public CorsFilter corsFilter() {
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowCredentials(true);
        //내 서버가 응답할때 json을 자바스크립트에서 처리할수 있게 할지 설정
        config.addAllowedOrigin("*"); // e.g. http://domain1.com
        //모든 ip응답을 허용
        config.addAllowedHeader("*"); //모든 헤더의 응답 허용
        config.addAllowedMethod("*"); //모든 post,get 등등을 허용

        ///api/** 이주소는 이 config를 따른다
        source.registerCorsConfiguration("/api/**", config);
        return new CorsFilter(source);
    }
}
