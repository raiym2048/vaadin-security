package com.example.application.service.impl;

import com.example.application.enitites.User;
import com.example.application.enums.Role;
import com.example.application.repo.UserRepository;
import com.example.application.service.AuthService;
import com.vaadin.flow.component.notification.Notification;
import com.vaadin.flow.router.NotFoundException;
import com.vaadin.flow.server.VaadinSession;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class AuthServiceImpl implements AuthService {
    private final AuthenticationManager authenticationManager;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public AuthServiceImpl(AuthenticationManager authenticationManager, UserRepository userRepository, PasswordEncoder passwordEncoder) {
        this.authenticationManager = authenticationManager;
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public Optional<User> getUser(String username, String password) {
        Optional<User> user;
        try {
            Authentication authentication = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(
                    username,
                    password));

            // Set the authentication result into the SecurityContext
            SecurityContextHolder.getContext().setAuthentication(authentication);

            user = userRepository.findByEmail(username);
            if (user.isPresent()){
                System.out.println("Success auth");
            }



        } catch (AuthenticationException e) {
            System.out.println("Not success auth");

            return Optional.empty();
        }
        return user;
    }
    @Override
    public void login(String emailField, String passwordField) {
        try {
            Authentication authentication =
                    authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(
                            emailField, passwordField
                    ));
            VaadinSession.getCurrent().getSession().setAttribute("email", emailField);
            VaadinSession.getCurrent().getSession().setAttribute("user", userRepository.findByEmail(emailField).get());
            VaadinSession.getCurrent().setAttribute(Authentication.class, authentication);
            VaadinSession.getCurrent().setAttribute("user", authentication.getPrincipal());
            SecurityContextHolder.getContext().setAuthentication(authentication);
            Notification.show("login succ");

        }catch (Exception e){
            Notification.show("error login");
            throw new BadCredentialsException("Incorrect email or password");
        }

    }

    @Override
    public void register(String email, String password) {
        if (userRepository.findByEmail(email).isPresent())
            throw new NotFoundException("user is present");

        User user = new User();
        user.setEmail(email);
        user.setRole(Role.USER);
        user.setPassword(passwordEncoder.encode(password));
        userRepository.save(user);

    }
}
