package com.demo.security.rls;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

/** Registreert de {@link RlsHandlerInterceptor} op alle gecombineerde demo-endpoints. */
@Configuration
public class RlsConfig implements WebMvcConfigurer {

    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        registry.addInterceptor(new RlsHandlerInterceptor())
                .addPathPatterns("/v1/poc-6/**");
    }
}
