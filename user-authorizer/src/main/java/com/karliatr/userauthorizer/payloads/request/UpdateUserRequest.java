package com.karliatr.userauthorizer.payloads.request;

import javax.validation.constraints.NotBlank;

public class UpdateUserRequest {
    @NotBlank
    private Long id;

    private String email;

    private String phoneNumber;

    public Long getId() {
        return id;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getPhoneNumber() {
        return phoneNumber;
    }

    public void setPhoneNumber(String phoneNumber) {
        this.phoneNumber = phoneNumber;
    }
}
