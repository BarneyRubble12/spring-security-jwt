package com.bedrock.springsecurityjwt.controller;

import com.bedrock.springsecurityjwt.exception.AuthenticationException;
import com.bedrock.springsecurityjwt.models.AuthRequest;
import com.bedrock.springsecurityjwt.models.AuthResponse;
import com.bedrock.springsecurityjwt.service.MyUserDetailsService;
import com.bedrock.springsecurityjwt.util.JwtUtil;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
public class HelloController {

  private final AuthenticationManager authenticationManager;
  private final MyUserDetailsService userDetailsService;
  private final JwtUtil jwtUtil;

  @SneakyThrows
  @PostMapping(value = "/authenticate", consumes = MediaType.APPLICATION_JSON_VALUE)
  public ResponseEntity<AuthResponse> authenticate(@RequestBody AuthRequest request) {
    var usernamePasswordAuthenticationToken =
        new UsernamePasswordAuthenticationToken(request.getUsername(), request.getPassword());

    try {
      authenticationManager
          .authenticate(usernamePasswordAuthenticationToken);
    } catch (BadCredentialsException e) {
      throw new AuthenticationException("Incorrect username or password", e);
    }

    final var userDetails = userDetailsService.loadUserByUsername(request.getUsername());
    final var jwt = jwtUtil.generateToken(userDetails);

    return ResponseEntity.ok(new AuthResponse(jwt));
  }

  @GetMapping("/hello")
  public String hello() {
    return "hello world!";
  }

}
