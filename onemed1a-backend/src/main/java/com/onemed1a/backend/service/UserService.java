package com.onemed1a.backend.service;

import com.onemed1a.backend.dto.CreateUserDTO;
import com.onemed1a.backend.dto.LoginRequestDTO;
import com.onemed1a.backend.dto.UpdateUserDTO;
import com.onemed1a.backend.dto.UserDTO;
import com.onemed1a.backend.model.User;
import com.onemed1a.backend.repository.UserRepository;
import com.onemed1a.backend.security.JwtTokenProvider;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import java.util.Arrays;
import java.util.Optional;
import java.util.UUID;

@Service
@RequiredArgsConstructor
@Transactional
public class UserService {

    private static final String USER_NOT_FOUND = "User not found";

    private final UserRepository repo;
    private final PasswordEncoder passwordEncoder;
    private final JwtTokenProvider jwtTokenProvider;

    // --- Registration ---
    public UserDTO create(CreateUserDTO dto) {


        if (repo.existsByEmail(dto.getEmail())) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "Email already in use");
        }

        User user = User.builder()
                .firstName(dto.getFirstName())
                .lastName(dto.getLastName())
                .email(dto.getEmail())
                .gender(dto.getGender())
                .dateOfBirth(dto.getDateOfBirth())
                .password(passwordEncoder.encode(dto.getPassword()))
                .active(true)
                .build();

        return map(repo.save(user));
    }

    // --- Login ---

    public void checkCredentials(LoginRequestDTO body, HttpServletResponse response) {

        System.out.println("checked credentials called");
        User user = repo.findByEmail(body.getEmail())
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, USER_NOT_FOUND));

        System.out.println("user active: " + user.isActive());
        if (!user.isActive()) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "User is inactive");
        }

        System.out.println("password matches: " + passwordEncoder.matches(body.getPassword(), user.getPassword()));
        if (!passwordEncoder.matches(body.getPassword(), user.getPassword())) { 
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid credentials");
        }

        System.out.println("generating token");
        // Generate JWT token and set it as HttpOnly cookie
        String token = jwtTokenProvider.generateToken(user.getId());
        ResponseCookie cookie = buildAccessTokenCookie(token, 0);

        System.out.println("setting cookie");
        response.addHeader(HttpHeaders.SET_COOKIE, cookie.toString());
    }

    public void logout(HttpServletResponse response) {
        ResponseCookie cookie = buildAccessTokenCookie("", 0);
        response.addHeader(HttpHeaders.SET_COOKIE, cookie.toString());
    }

    // --- Get current user from token ---

    public UserDTO getCurrentUser(HttpServletRequest request) {
        String token = Arrays.stream(Optional.ofNullable(request.getCookies()).orElse(new Cookie[0]))
                .filter(c -> "access_token".equals(c.getName()))
                .map(Cookie::getValue)
                .findFirst()
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Missing token"));

        System.out.println("validating token");
        UUID userId = jwtTokenProvider.validateTokenAndGetUserId(token);
        User user = repo.findById(userId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, USER_NOT_FOUND));

        return map(user);
    }

    // --- Profile operations ---

    public UserDTO getById(UUID id) {
        User user = repo.findById(id)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, USER_NOT_FOUND));

        if (!user.isActive()) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, USER_NOT_FOUND);
        }

        return map(user);
    }

    public UserDTO updateProfile(UUID id, UpdateUserDTO dto) {
        User user = repo.findById(id)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, USER_NOT_FOUND));

        if (!user.isActive()) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, USER_NOT_FOUND);
        }

        if (dto.getFirstName() != null) user.setFirstName(dto.getFirstName());
        if (dto.getLastName() != null) user.setLastName(dto.getLastName());
        if (dto.getGender() != null) user.setGender(dto.getGender());
        if (dto.getDateOfBirth() != null) user.setDateOfBirth(dto.getDateOfBirth());

        return map(repo.save(user));
    }

    public void deactivate(UUID id) {
        User user = repo.findById(id)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, USER_NOT_FOUND));

        if (!user.isActive()) return;

        user.setActive(false);
        repo.save(user);
    }

    private ResponseCookie buildAccessTokenCookie(String token, long maxAge) {
        return ResponseCookie.from("access_token", token)
                .httpOnly(true)
                .secure(false) // Set to true in production with HTTPS
                .sameSite("Lax")
                .path("/")
                .maxAge(maxAge)
                .build();
    }


    // ---- mapping ----
    private UserDTO map(User u) {
        return UserDTO.builder()
                .id(u.getId())
                .firstName(u.getFirstName())
                .lastName(u.getLastName())
                .email(u.getEmail())
                .gender(u.getGender())
                .dateOfBirth(u.getDateOfBirth())
                .active(u.isActive())
                .createdAt(u.getCreatedAt())
                .build();
    }
}
