package com.bsu.kbrs.utils;

public class SessionPair {
    private String userId;
    private Long expirationDate;

    public SessionPair() {
    }

    public SessionPair(String userId, Long expirationDate) {
        this.userId = userId;
        this.expirationDate = expirationDate;
    }

    public String getUserId() {
        return userId;
    }

    public void setUserId(String userId) {
        this.userId = userId;
    }

    public Long getExpirationDate() {
        return expirationDate;
    }

    public void setExpirationDate(Long expirationDate) {
        this.expirationDate = expirationDate;
    }
}
