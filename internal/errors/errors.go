// Copyright 2025 Canonical Ltd.
// SPDX-License-Identifier: AGPL-3.0-only

// Package errors provides standardized error handling for the Secure Token Service.
package errors

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
)

// ErrorCode represents a machine-readable error code
type ErrorCode string

// Error codes for API responses
const (
	// Authentication errors
	ErrCodeInvalidState          ErrorCode = "INVALID_STATE"
	ErrCodeInvalidNonce          ErrorCode = "INVALID_NONCE"
	ErrCodeMissingCode           ErrorCode = "MISSING_CODE"
	ErrCodeOIDCError             ErrorCode = "OIDC_ERROR"
	ErrCodeTokenExchangeFailed   ErrorCode = "TOKEN_EXCHANGE_FAILED"
	ErrCodeSessionCreationFailed ErrorCode = "SESSION_CREATION_FAILED"

	// Session errors
	ErrCodeSessionNotFound ErrorCode = "SESSION_NOT_FOUND"
	ErrCodeSessionInvalid  ErrorCode = "SESSION_INVALID"
	ErrCodeSessionExpired  ErrorCode = "SESSION_EXPIRED"

	// JWT errors
	ErrCodeJWTMintingFailed    ErrorCode = "JWT_MINTING_FAILED"
	ErrCodeJWTInvalid          ErrorCode = "JWT_INVALID"
	ErrCodeJWKSRetrievalFailed ErrorCode = "JWKS_RETRIEVAL_FAILED"

	// Internal errors
	ErrCodeInternalError ErrorCode = "INTERNAL_ERROR"
	ErrCodeDatabaseError ErrorCode = "DATABASE_ERROR"
	ErrCodeCacheError    ErrorCode = "CACHE_ERROR"
)

// AppError represents an application error with code and context
type AppError struct {
	Code       ErrorCode         `json:"code"`
	Message    string            `json:"message"`
	StatusCode int               `json:"-"`
	Details    map[string]string `json:"details,omitempty"`
	Err        error             `json:"-"` // Wrapped error for logging
}

// Error implements the error interface
func (e *AppError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%s: %s (%v)", e.Code, e.Message, e.Err)
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

// Unwrap returns the wrapped error
func (e *AppError) Unwrap() error {
	return e.Err
}

// New creates a new AppError
func New(code ErrorCode, message string, statusCode int) *AppError {
	return &AppError{
		Code:       code,
		Message:    message,
		StatusCode: statusCode,
	}
}

// Wrap creates an AppError wrapping an existing error
func Wrap(code ErrorCode, message string, statusCode int, err error) *AppError {
	return &AppError{
		Code:       code,
		Message:    message,
		StatusCode: statusCode,
		Err:        err,
	}
}

// WithDetails adds details to an AppError
func (e *AppError) WithDetails(key, value string) *AppError {
	if e.Details == nil {
		e.Details = make(map[string]string)
	}
	e.Details[key] = value
	return e
}

// WriteJSON writes an error response as JSON
func (e *AppError) WriteJSON(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(e.StatusCode)

	if err := json.NewEncoder(w).Encode(e); err != nil {
		log.Printf("Failed to encode error response: %v", err)
	}
}

// WriteText writes an error response as plain text
func (e *AppError) WriteText(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(e.StatusCode)
	fmt.Fprintf(w, "%s: %s\n", e.Code, e.Message)
}

// LogAndWrite logs the full error (including wrapped error) and writes response
func (e *AppError) LogAndWrite(w http.ResponseWriter, format string) {
	if e.Err != nil {
		log.Printf("%s: %s (wrapped: %v)", e.Code, e.Message, e.Err)
	} else {
		log.Printf("%s: %s", e.Code, e.Message)
	}

	// Decide format based on request
	if format == "json" {
		e.WriteJSON(w)
	} else {
		e.WriteText(w)
	}
}

// Common error constructors

// InvalidState creates an INVALID_STATE error
func InvalidState(message string) *AppError {
	return New(ErrCodeInvalidState, message, http.StatusBadRequest)
}

// InvalidNonce creates an INVALID_NONCE error
func InvalidNonce(message string) *AppError {
	return New(ErrCodeInvalidNonce, message, http.StatusBadRequest)
}

// MissingCode creates a MISSING_CODE error
func MissingCode(message string) *AppError {
	return New(ErrCodeMissingCode, message, http.StatusBadRequest)
}

// OIDCError creates an OIDC_ERROR error
func OIDCError(message string, err error) *AppError {
	return Wrap(ErrCodeOIDCError, message, http.StatusBadRequest, err)
}

// TokenExchangeFailed creates a TOKEN_EXCHANGE_FAILED error
func TokenExchangeFailed(err error) *AppError {
	return Wrap(ErrCodeTokenExchangeFailed, "Failed to exchange authorization code", http.StatusInternalServerError, err)
}

// SessionCreationFailed creates a SESSION_CREATION_FAILED error
func SessionCreationFailed(err error) *AppError {
	return Wrap(ErrCodeSessionCreationFailed, "Failed to create session", http.StatusInternalServerError, err)
}

// SessionNotFound creates a SESSION_NOT_FOUND error
func SessionNotFound() *AppError {
	return New(ErrCodeSessionNotFound, "Session not found", http.StatusUnauthorized)
}

// SessionInvalid creates a SESSION_INVALID error
func SessionInvalid(message string) *AppError {
	return New(ErrCodeSessionInvalid, message, http.StatusUnauthorized)
}

// SessionExpired creates a SESSION_EXPIRED error
func SessionExpired() *AppError {
	return New(ErrCodeSessionExpired, "Session has expired", http.StatusUnauthorized)
}

// JWTMintingFailed creates a JWT_MINTING_FAILED error
func JWTMintingFailed(err error) *AppError {
	return Wrap(ErrCodeJWTMintingFailed, "Failed to mint JWT", http.StatusInternalServerError, err)
}

// JWTInvalid creates a JWT_INVALID error
func JWTInvalid(message string) *AppError {
	return New(ErrCodeJWTInvalid, message, http.StatusUnauthorized)
}

// JWKSRetrievalFailed creates a JWKS_RETRIEVAL_FAILED error
func JWKSRetrievalFailed(err error) *AppError {
	return Wrap(ErrCodeJWKSRetrievalFailed, "Failed to retrieve JWKS", http.StatusInternalServerError, err)
}

// InternalError creates an INTERNAL_ERROR
func InternalError(message string, err error) *AppError {
	return Wrap(ErrCodeInternalError, message, http.StatusInternalServerError, err)
}

// DatabaseError creates a DATABASE_ERROR
func DatabaseError(operation string, err error) *AppError {
	return Wrap(ErrCodeDatabaseError, fmt.Sprintf("Database error during %s", operation), http.StatusInternalServerError, err)
}

// CacheError creates a CACHE_ERROR
func CacheError(operation string, err error) *AppError {
	return Wrap(ErrCodeCacheError, fmt.Sprintf("Cache error during %s", operation), http.StatusInternalServerError, err)
}
