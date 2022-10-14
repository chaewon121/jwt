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

      config.setAllowCredentials(true); //내 서버가 응답할때 자바스크립트에서 가능하게
      config.addAllowedOrigin("*"); // 모든 ip에서 허용
      config.addAllowedHeader("*"); //모든헤더응답 허용
      config.addAllowedMethod("*");//put등등

      //이 필터를 따라라
      source.registerCorsConfiguration("/api/**", config);
      return new CorsFilter(source);
   }

}
