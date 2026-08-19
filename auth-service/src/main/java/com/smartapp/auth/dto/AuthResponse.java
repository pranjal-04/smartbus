package com.smartapp.auth.dto;

public record AuthResponse(
        String token,
        String tokenType
) {
}