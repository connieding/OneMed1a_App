package com.onemed1a.backend.controller;

import java.util.List;
import java.util.UUID;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import com.onemed1a.backend.dto.CreateUserDTO;
import com.onemed1a.backend.dto.LoginRequestDTO;
import com.onemed1a.backend.dto.UpdateUserDTO;
import com.onemed1a.backend.dto.UserDTO;
import com.onemed1a.backend.model.User;
import com.onemed1a.backend.repository.UserRepository;
import com.onemed1a.backend.service.UserService;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;

@RestController
@RequestMapping("/api/v1")
@RequiredArgsConstructor
public class UserController {

    private final UserService userService;
    private final UserRepository userRepository;

    // --- Public / Admin routes ---
    
    /** 
     * Creates a new user.
     * 
     * @param body the user creation data
     * @return the created user
     */
    @PostMapping("/createuser")
    public ResponseEntity<UserDTO> create(@Valid @RequestBody CreateUserDTO body) {
        return ResponseEntity.status(HttpStatus.CREATED).body(userService.create(body));
    }

    /** 
     * Gets a user by ID.
     * 
     * @param id the user ID
     * @return the user
     */
    @GetMapping("/users/{id}")
    public UserDTO getById(@PathVariable UUID id) {
        return userService.getById(id);
    }

    @GetMapping("/allusers")
    public List<User> getAllUsers() {
        return userRepository.findAll();
    }

    /** 
     * Checks user credentials and sets a JWT token as an HttpOnly cookie if valid.
     * 
     * @param body the login request data
     * @param response the HTTP response
     * @return 200 OK if credentials are valid
     */
    @PostMapping("/accountcheck")
    public ResponseEntity<UserDTO> checkSignIn(@Valid @RequestBody LoginRequestDTO body, HttpServletResponse response) {

        userService.checkCredentials(body, response);
        System.out.println("account check successful");
        return ResponseEntity.ok().build();
    }

    /** 
     * Logs out the user by clearing the JWT token cookie.
     * 
     * @param response the HTTP response
     * @return 200 OK
     */
    @PostMapping("/logout")
    public ResponseEntity<Void> logout(HttpServletResponse response) {
        userService.logout(response);
        return ResponseEntity.ok().build();
    }

    // --- Current user (/me) routes ---

    /**
     * Gets the profile of the current user.
     *  
     * @param request
     * @return
     */
    @GetMapping("/getprofile")
    public UserDTO getProfile(HttpServletRequest request) {
        System.out.println("In UserController.getProfile");
        return userService.getCurrentUser(request);
    }

    /**
     * Updates the profile of the current user.
     * 
     * @param request the HTTP request
     * @param body the updated user profile data
     * @return the updated user profile
     */
    @PutMapping("/me")
    public UserDTO updateMe(HttpServletRequest request, @Valid @RequestBody UpdateUserDTO body) {
        UUID userId = userService.getCurrentUser(request).getId();

        return userService.updateProfile(userId, body);
    }

    /**
     * Deactivates the current user's account.
     * 
     * @param request the HTTP request
     */
    @DeleteMapping("/me")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void deactivate(HttpServletRequest request) {
        UUID userId = userService.getCurrentUser(request).getId();
        
        userService.deactivate(userId);
    }
}
