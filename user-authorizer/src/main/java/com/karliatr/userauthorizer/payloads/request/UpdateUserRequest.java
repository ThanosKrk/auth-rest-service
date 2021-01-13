package com.karliatr.userauthorizer.payloads.request;

import javax.validation.constraints.NotBlank;

public class UpdateUserRequest {
    @NotBlank
    private Long id;

    private String username;

    private String email;

    public Long getId() {
        return id;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }
}
