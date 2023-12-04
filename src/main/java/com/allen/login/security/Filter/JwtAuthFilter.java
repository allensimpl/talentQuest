package com.allen.login.security.Filter;

import com.allen.login.api.service.UserService;
import com.allen.login.dto.SubjectDto;
import com.allen.login.security.utils.JwtTokenUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.annotation.WebFilter;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@WebFilter
@Component
@Order(2)
public class JwtAuthFilter extends OncePerRequestFilter {
    @Autowired
    private JwtTokenUtil jwtTokenUtil;

    @Autowired
    private UserService userService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String url = String.valueOf(request.getRequestURL());
        String header = request.getHeader("v1r2a3m@l#e_o8");
        String redisKey =null;
        String authToken = null;

        if(!url.contains("/secure/")){
            filterChain.doFilter(request,response);
            return;
        }
        if(header!=null && header.startsWith("Bearer ")){
            authToken = header.replace("Bearer ","");
            redisKey = jwtTokenUtil.getRedisToken(header);
//            SubjectDto subjectDto = userService
        }
        filterChain.doFilter(request,response);
    }
}
