package com.karliatr.userauthorizer.controllers;

import com.karliatr.userauthorizer.models.ERole;
import com.karliatr.userauthorizer.models.Role;
import com.karliatr.userauthorizer.models.User;
import com.karliatr.userauthorizer.payloads.request.LoginRequest;
import com.karliatr.userauthorizer.payloads.request.SignupRequest;
import com.karliatr.userauthorizer.payloads.request.UpdateUserRequest;
import com.karliatr.userauthorizer.payloads.response.JwtResponse;
import com.karliatr.userauthorizer.payloads.response.MessageResponse;
import com.karliatr.userauthorizer.repository.RoleRepository;
import com.karliatr.userauthorizer.repository.UserRepository;
import com.karliatr.userauthorizer.security.jwt.JwtUtils;
import com.karliatr.userauthorizer.security.services.UserDetailsImpl;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/api/auth")
public class AuthController {
    @Autowired
    AuthenticationManager authenticationManager;

    @Autowired
    UserRepository userRepository;

    @Autowired
    RoleRepository roleRepository;

    @Autowired
    PasswordEncoder encoder;

    @Autowired
    JwtUtils jwtUtils;

    @PostMapping("/signin")
    public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginRequest loginRequest) {

        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword()));

        SecurityContextHolder.getContext().setAuthentication(authentication);
        String jwt = jwtUtils.generateJwtToken(authentication);

        UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();
        List<String> roles = userDetails.getAuthorities().stream()
                .map(item -> item.getAuthority())
                .collect(Collectors.toList());

        return ResponseEntity.ok(new JwtResponse(jwt,
                userDetails.getId(),
                userDetails.getUsername(),
                userDetails.getFirstName(),
                userDetails.getLastName(),
                userDetails.getAfm(),
                userDetails.getEmail(),
                userDetails.getEmploymentStatus(),
                userDetails.getPhoneNumber(),
                roles));
    }

    @PostMapping("/updateUser")
    @PreAuthorize("hasRole('USER')")
    public ResponseEntity<?> updateUser(@Valid @RequestBody UpdateUserRequest newUsernameRequest) {
        //System.out.printf("IN update user function!\n");
        Optional<User> updatedUser = userRepository.getUserById(newUsernameRequest.getId());

        if (!updatedUser.isPresent()) {
            return ResponseEntity
                    .badRequest()
                    .body(new MessageResponse("Δεν βρέθηκε ο συγκεκριμένος χρήστης για να ενημερωθεί!"));
        }

        //Check if new email exists!
        if (!newUsernameRequest.getEmail().equals(updatedUser.get().getEmail()) && userRepository.existsByEmail(newUsernameRequest.getEmail())) {
            System.out.printf("\n%s\n", newUsernameRequest.getEmail());
            return ResponseEntity
                    .badRequest()
                    .body(new MessageResponse("Το συγκεκριμένο email χρησιμοποιείται!"));
        }

        if (newUsernameRequest.getEmail().isEmpty() || newUsernameRequest.getPhoneNumber().isEmpty()) {
            return ResponseEntity
                    .badRequest()
                    .body(new MessageResponse("Κενά πεδία, μη επιτρεπτά!"));
        }

        // Check if new email field is filled with new email
        if (newUsernameRequest.getEmail() != "" && newUsernameRequest.getEmail() != updatedUser.get().getEmail()) {
            System.out.println("Updating email!\n");
            updatedUser.get().setEmail(newUsernameRequest.getEmail());
        }

        // Check if new phone-number field is filled with new phone-number
        if (newUsernameRequest.getPhoneNumber() != "" && newUsernameRequest.getPhoneNumber() != updatedUser.get().getPhoneNumber()) {
            System.out.println("Updating phoneNumber!\n");
            updatedUser.get().setPhoneNumber(newUsernameRequest.getPhoneNumber());
        }

        userRepository.save(updatedUser.get());

        return ResponseEntity.ok(new MessageResponse("Ο χρήστης ενημερώθηκε με επιτυχία!"));
    }

    @PostMapping("/signup")
    public ResponseEntity<?> registerUser(@Valid @RequestBody SignupRequest signUpRequest) {
        if (userRepository.existsByUsername(signUpRequest.getUsername())) {
            return ResponseEntity
                    .badRequest()
                    .body(new MessageResponse("Το συγκεκριμένο όνομα χρήστη χρησιμοπειείται ήδη!"));
        }

        if (userRepository.existsByEmail(signUpRequest.getEmail())) {
            return ResponseEntity
                    .badRequest()
                    .body(new MessageResponse("Η συγκεκριμένη διεύθυνση email χρησιμοπειείται ήδη!"));
        }

        if (userRepository.existsByAfm(signUpRequest.getAfm())) {
            return ResponseEntity
                    .badRequest()
                    .body(new MessageResponse("Το συγκεκριμένο ΑΦΜ χρησιμοπειείται ήδη!"));
        }

        if (!signUpRequest.getEmploymentStatus().equals("employer") && !signUpRequest.getEmploymentStatus().equals("employee")) {
            return ResponseEntity
                    .badRequest()
                    .body(new MessageResponse("Επιλογή ρόλου αποκλειστικά μεταξύ εργαζόμενου και εργοδότη!"));
        }

        // Create new user's account
        User user = new User(signUpRequest.getUsername(),
                signUpRequest.getFirstName(),
                signUpRequest.getLastName(),
                signUpRequest.getAfm(),
                signUpRequest.getEmail(),
                signUpRequest.getEmploymentStatus(),
                signUpRequest.getPhoneNumber(),
                encoder.encode(signUpRequest.getPassword()));

        Set<String> strRoles = signUpRequest.getRole();
        Set<Role> roles = new HashSet<>();

        if (strRoles == null) {
            Role userRole = roleRepository.findByName(ERole.ROLE_USER)
                    .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
            roles.add(userRole);
        } else {
            strRoles.forEach(role -> {
                switch (role) {
                    case "admin":
                        Role adminRole = roleRepository.findByName(ERole.ROLE_ADMIN)
                                .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                        roles.add(adminRole);

                        break;
                    case "mod":
                        Role modRole = roleRepository.findByName(ERole.ROLE_MODERATOR)
                                .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                        roles.add(modRole);

                        break;
                    default:
                        Role userRole = roleRepository.findByName(ERole.ROLE_USER)
                                .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                        roles.add(userRole);
                }
            });
        }

        user.setRoles(roles);
        userRepository.save(user);

        return ResponseEntity.ok(new MessageResponse("Ο χρήστης δημιουργήθηκε με επιτυχία!"));
    }
}
