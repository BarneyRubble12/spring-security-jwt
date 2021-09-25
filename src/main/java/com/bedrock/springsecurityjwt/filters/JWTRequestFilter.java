package com.bedrock.springsecurityjwt.filters;

import com.bedrock.springsecurityjwt.service.MyUserDetailsService;
import com.bedrock.springsecurityjwt.util.JwtUtil;
import java.io.IOException;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

@Component
@RequiredArgsConstructor
public class JWTRequestFilter extends OncePerRequestFilter {

  private final MyUserDetailsService userDetailsService;
  private final JwtUtil jwtUtil;

  @Override
  protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
      FilterChain filterChain) throws ServletException, IOException {

    final var authorizationHeader = request.getHeader("Authorization");

    var username = "";
    var jwt = "";

    if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
      jwt = authorizationHeader.substring(7);
      username = jwtUtil.extractUserName(jwt);
    }

    if (!username.isEmpty() && SecurityContextHolder.getContext().getAuthentication() == null) {
      var userDetails = this.userDetailsService.loadUserByUsername(username);

      if (jwtUtil.validateToken(jwt, userDetails)) {
        var usernamePasswdAuthToken = new UsernamePasswordAuthenticationToken(userDetails, null,
            userDetails.getAuthorities());

        usernamePasswdAuthToken
            .setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

        SecurityContextHolder
            .getContext()
            .setAuthentication(usernamePasswdAuthToken);
      }
    }

    filterChain.doFilter(request, response);

  }
}
