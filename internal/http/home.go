// Copyright 2025 Canonical Ltd.
// SPDX-License-Identifier: AGPL-3.0-only

package httpserver

import (
	"fmt"
	"net/http"
	"time"

	"github.com/canonical/secure-token-service/internal/session"
	"go.uber.org/zap"
)

// handleHome displays user session information on the homepage
func (s *Server) handleHome(w http.ResponseWriter, r *http.Request) {
	// Try to get session cookie
	cookie, err := r.Cookie("session_id")

	// If no session cookie, show login page
	if err != nil || cookie.Value == "" {
		renderUnauthenticatedHome(w)
		return
	}

	// Decode session from cookie
	sessionID, err := s.cookieManager.Decode("session_id", cookie.Value)
	if err != nil {
		s.logger(r.Context()).Error("failed to decode session cookie", zap.Error(err))
		renderUnauthenticatedHome(w)
		return
	}

	// Get session from store
	sess, err := s.sessionStore.Get(r.Context(), sessionID)
	if err != nil || sess == nil {
		s.logger(r.Context()).Error("failed to get session", zap.String("session_id", sessionID), zap.Error(err))
		renderUnauthenticatedHome(w)
		return
	}

	// Render authenticated home page with session data
	renderAuthenticatedHome(w, sess)
}

// renderUnauthenticatedHome renders the homepage for unauthenticated users
func renderUnauthenticatedHome(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	html := `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Secure Token Service</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }
        .container {
            background: white;
            border-radius: 16px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            padding: 60px 40px;
            max-width: 480px;
            width: 100%;
            text-align: center;
        }
        h1 {
            color: #333;
            font-size: 32px;
            margin-bottom: 12px;
            font-weight: 700;
        }
        p {
            color: #666;
            font-size: 16px;
            line-height: 1.6;
            margin-bottom: 32px;
        }
        .btn {
            display: inline-block;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 16px 48px;
            border-radius: 8px;
            text-decoration: none;
            font-weight: 600;
            font-size: 16px;
            transition: transform 0.2s, box-shadow 0.2s;
            box-shadow: 0 4px 12px rgba(102, 126, 234, 0.4);
        }
        .btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 6px 20px rgba(102, 126, 234, 0.6);
        }
        .icon {
            font-size: 64px;
            margin-bottom: 24px;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="icon">🔐</div>
        <h1>Secure Token Service</h1>
        <p>Welcome! Please log in to view your session information and tokens.</p>
        <a href="/auth/login" class="btn">Log In</a>
    </div>
</body>
</html>`
	w.Write([]byte(html))
}

// renderAuthenticatedHome renders the homepage for authenticated users with session data
func renderAuthenticatedHome(w http.ResponseWriter, sess *session.Session) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	// Mask tokens for security (show last 10 chars)
	maskToken := func(token string) string {
		if len(token) <= 10 {
			return "***"
		}
		return "..." + token[len(token)-10:]
	}

	accessToken := maskToken(sess.AccessToken)
	idToken := maskToken(sess.IDToken)
	refreshToken := "N/A"
	if sess.RefreshToken != "" {
		refreshToken = maskToken(sess.RefreshToken)
	}

	html := fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Session Info - Secure Token Service</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #667eea 0%%, #764ba2 100%%);
            min-height: 100vh;
            padding: 40px 20px;
        }
        .container {
            max-width: 800px;
            margin: 0 auto;
        }
        .card {
            background: white;
            border-radius: 16px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            padding: 40px;
            margin-bottom: 24px;
        }
        h1 {
            color: #333;
            font-size: 32px;
            margin-bottom: 8px;
            font-weight: 700;
        }
        .subtitle {
            color: #888;
            font-size: 14px;
            margin-bottom: 32px;
        }
        .info-grid {
            display: grid;
            gap: 24px;
        }
        .info-item {
            border-bottom: 1px solid #f0f0f0;
            padding-bottom: 16px;
        }
        .info-item:last-child {
            border-bottom: none;
            padding-bottom: 0;
        }
        .label {
            font-size: 12px;
            color: #888;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            margin-bottom: 8px;
            font-weight: 600;
        }
        .value {
            font-size: 16px;
            color: #333;
            font-family: 'Monaco', 'Courier New', monospace;
            word-break: break-all;
        }
        .status {
            display: inline-block;
            padding: 6px 12px;
            border-radius: 20px;
            font-size: 14px;
            font-weight: 600;
        }
        .status.active {
            background: #d4edda;
            color: #155724;
        }
        .status.expired {
            background: #f8d7da;
            color: #721c24;
        }
        .btn {
            display: inline-block;
            background: #dc3545;
            color: white;
            padding: 12px 32px;
            border-radius: 8px;
            text-decoration: none;
            font-weight: 600;
            font-size: 14px;
            transition: transform 0.2s, box-shadow 0.2s;
            border: none;
            cursor: pointer;
            box-shadow: 0 4px 12px rgba(220, 53, 69, 0.3);
        }
        .btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 6px 20px rgba(220, 53, 69, 0.5);
            background: #c82333;
        }
        .logout-form {
            text-align: center;
            margin-top: 24px;
        }
        .icon {
            font-size: 48px;
            margin-bottom: 16px;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="card">
            <div class="icon">👤</div>
            <h1>Session Information</h1>
            <p class="subtitle">Authenticated as %s</p>
            
            <div class="info-grid">
                <div class="info-item">
                    <div class="label">User ID</div>
                    <div class="value">%s</div>
                </div>
                <div class="info-item">
                    <div class="label">Session ID</div>
                    <div class="value">%s</div>
                </div>
                <div class="info-item">
                    <div class="label">Session Status</div>
                    <div class="value">
                        <span class="status %s">%s</span>
                    </div>
                </div>
                <div class="info-item">
                    <div class="label">Expires At</div>
                    <div class="value">%s</div>
                </div>
                <div class="info-item">
                    <div class="label">Created At</div>
                    <div class="value">%s</div>
                </div>
            </div>
        </div>

        <div class="card">
            <h2 style="color: #333; font-size: 24px; margin-bottom: 24px;">🔑 Tokens</h2>
            <div class="info-grid">
                <div class="info-item">
                    <div class="label">Access Token</div>
                    <div class="value">%s</div>
                </div>
                <div class="info-item">
                    <div class="label">ID Token</div>
                    <div class="value">%s</div>
                </div>
                <div class="info-item">
                    <div class="label">Refresh Token</div>
                    <div class="value">%s</div>
                </div>
            </div>
        </div>

        <form method="POST" action="/auth/logout" class="logout-form">
            <button type="submit" class="btn">Logout</button>
        </form>
    </div>
</body>
</html>`,
		sess.UserID,
		sess.UserID,
		sess.SessionID,
		getStatusClass(sess.ExpiresAt),
		getStatusText(sess.ExpiresAt),
		sess.ExpiresAt.Format("2006-01-02 15:04:05 MST"),
		sess.CreatedAt.Format("2006-01-02 15:04:05 MST"),
		accessToken,
		idToken,
		refreshToken,
	)

	w.Write([]byte(html))
}

// getStatusClass returns CSS class for session status
func getStatusClass(expiresAt time.Time) string {
	if time.Now().Before(expiresAt) {
		return "active"
	}
	return "expired"
}

// getStatusText returns text for session status
func getStatusText(expiresAt time.Time) string {
	if time.Now().Before(expiresAt) {
		return "Active"
	}
	return "Expired"
}
