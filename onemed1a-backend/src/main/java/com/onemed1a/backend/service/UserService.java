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

/* Service class for managing user operations such as registration, login, profile management, and deactivation. */
@Service
@RequiredArgsConstructor
@Transactional
public class UserService {

    private static final String USER_NOT_FOUND = "User not found";

    private final UserRepository repo;
    private final PasswordEncoder passwordEncoder;
    private final JwtTokenProvider jwtTokenProvider;

    // --- Registration ---

    /**
     * Creates a new user.
     * @param dto the user creation data
     * @return the created user
     */
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

    /**
     * Checks user credentials and sets JWT token as HttpOnly cookie if valid.
     * 
     * @param body the login request data
     * @param response the HTTP response to set the cookie
     */
    public void checkCredentials(LoginRequestDTO body, HttpServletResponse response) {

        User user = repo.findByEmail(body.getEmail())
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, USER_NOT_FOUND));

        if (!user.isActive()) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "User is inactive");
        }

        if (!passwordEncoder.matches(body.getPassword(), user.getPassword())) { 
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid credentials");
        }

        // Generate JWT token and set it as HttpOnly cookie
        String token = jwtTokenProvider.generateToken(user.getId());
        ResponseCookie cookie = buildAccessTokenCookie(token, 86400); // 1 day

        response.addHeader(HttpHeaders.SET_COOKIE, cookie.toString());
    }

    /**
     * Logs out the user by clearing the JWT token cookie.
     * 
     * @param response the HTTP response to clear the cookie
     */
    public void logout(HttpServletResponse response) {
        ResponseCookie cookie = buildAccessTokenCookie("", 0);
        response.addHeader(HttpHeaders.SET_COOKIE, cookie.toString());
    }

    // --- Get current user from token ---

    /**
     * Gets the current user based on the JWT token in the request cookies.
     * 
     * @param request the HTTP request containing the cookies
     * @return the current user's profile
     */
    public UserDTO getCurrentUser(HttpServletRequest request) {
        String token = Arrays.stream(Optional.ofNullable(request.getCookies()).orElse(new Cookie[0]))
                .filter(c -> "access_token".equals(c.getName()))
                .map(Cookie::getValue)
                .findFirst()
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Missing token"));

        UUID userId = jwtTokenProvider.validateTokenAndGetUserId(token);
        User user = repo.findById(userId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, USER_NOT_FOUND));

        return map(user);
    }

    // --- Profile operations ---

    /**
     * Gets a user by ID.
     * 
     * * @param id the user ID
     * @return the user
     */
    public UserDTO getById(UUID id) {
        User user = repo.findById(id)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, USER_NOT_FOUND));

        if (!user.isActive()) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, USER_NOT_FOUND);
        }

        return map(user);
    }

    /**
     * Updates a user's profile.
     * 
     * @param id the user ID
     * @param dto the update data
     * @return the updated user
     */
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

    /**
     * Deactivates a user account.
     * 
     * @param id the user ID
     */
    public void deactivate(UUID id) {
        User user = repo.findById(id)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, USER_NOT_FOUND));

        if (!user.isActive()) return;

        user.setActive(false);
        repo.save(user);
    }

    // --- Helpers ---

    /**
     * Builds an HttpOnly cookie for the access token.
     * 
     * @param token the JWT token
     * @param maxAge the max age of the cookie in seconds
     * @return
     */
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
