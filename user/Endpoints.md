# API Usage Examples and Test Cases

# Points de terminaison API disponibles :
POST /auth/buyer/register/        - Inscription d'un acheteur  
POST /auth/merchant/register/     - Inscription d'un commerçant  
POST /auth/login/                 - Connexion utilisateur  
POST /auth/logout/                - Déconnexion utilisateur  
GET/PUT /auth/profile/            - Gestion du profil  
GET /auth/status/                 - Statut de l'utilisateur  
POST /auth/password/change/       - Changer le mot de passe  
POST /auth/password/reset/request/ - Demander une réinitialisation du mot de passe  
POST /auth/password/reset/confirm/ - Confirmer la réinitialisation du mot de passe  
POST /auth/email/verify/          - Vérifier l'e-mail avec un code OTP  
POST /auth/email/resend-otp/      - Renvoyer le code OTP  


"""
1. BUYER REGISTRATION
POST /auth/buyer/register/
Content-Type: application/json

{
    "email": "buyer@example.com",
    "nom_complet": "John Doe",
    "adrese": "123 Main St, City",
    "numero_telephone": "+1234567890",
    "password": "securepassword123",
    "password_confirm": "securepassword123",
    "preferred_payment_method": "credit_card",
    "date_of_birth": "1990-01-01"
}

Response:
{
    "message": "Buyer account created successfully",
    "user_id": 1,
    "email": "buyer@example.com",
    "token": "abc123token",
    "email_sent": true,
    "verification_required": true
}
"""

"""
2. MERCHANT REGISTRATION
POST /auth/merchant/register/
Content-Type: application/json

{
    "email": "merchant@example.com",
    "nom_complet": "Jane Smith",
    "adrese": "456 Business Ave",
    "numero_telephone": "+1987654321",
    "password": "merchantpass123",
    "password_confirm": "merchantpass123",
    "business_name": "Smith's Store",
    "website": "https://smithstore.com",
    "category": "electronics",
    "bank_account_number": "1234567890123456"
}

Response:
{
    "message": "Merchant account created successfully",
    "user_id": 2,
    "email": "merchant@example.com",
    "token": "def456token",
    "email_sent": true,
    "verification_required": true,
    "note": "Account requires admin verification before activation"
}
"""

"""
3. LOGIN
POST /auth/login/
Content-Type: application/json

{
    "email": "buyer@example.com",
    "password": "securepassword123"
}

Response:
{
    "message": "Login successful",
    "token": "abc123token",
    "user_type": "buyer",
    "user_id": 1,
    "email": "buyer@example.com",
    "is_verified": false
}
"""

"""
4. EMAIL VERIFICATION
POST /auth/email/verify/
Content-Type: application/json

{
    "email": "buyer@example.com",
    "otp_code": "123456"
}

Response:
{
    "message": "Email verified successfully",
    "is_verified": true
}
"""

"""
5. GET USER PROFILE
GET /auth/profile/
Authorization: Token abc123token

Response (for buyer):
{
    "id": 1,
    "email": "buyer@example.com",
    "nom_complet": "John Doe",
    "adrese": "123 Main St, City",
    "numero_telephone": "+1234567890",
    "preferred_payment_method": "credit_card",
    "date_of_birth": "1990-01-01",
    "phone_verified": false,
    "is_verified": true,
    "date_verified": "2024-01-15T10:30:00Z",
    "date_joined": "2024-01-15T10:00:00Z"
}
"""

"""
6. UPDATE USER PROFILE
PUT /auth/profile/
Authorization: Token abc123token
Content-Type: application/json

{
    "nom_complet": "John Updated Doe",
    "adrese": "789 New Address St",
    "numero_telephone": "+1555666777",
    "preferred_payment_method": "paypal"
}

Response:
{
    "id": 1,
    "email": "buyer@example.com",
    "nom_complet": "John Updated Doe",
    "adrese": "789 New Address St",
    "numero_telephone": "+1555666777",
    "preferred_payment_method": "paypal",
    "date_of_birth": "1990-01-01",
    "phone_verified": false,
    "is_verified": true,
    "date_verified": "2024-01-15T10:30:00Z",
    "date_joined": "2024-01-15T10:00:00Z"
}
"""

"""
7. CHANGE PASSWORD
POST /auth/password/change/
Authorization: Token abc123token
Content-Type: application/json

{
    "old_password": "securepassword123",
    "new_password": "newsecurepass456",
    "new_password_confirm": "newsecurepass456"
}

Response:
{
    "message": "Password changed successfully. Please login again."
}
"""

"""
8. PASSWORD RESET REQUEST
POST /auth/password/reset/request/
Content-Type: application/json

{
    "email": "buyer@example.com"
}

Response:
{
    "message": "Password reset code sent to your email",
    "email_sent": true
}
"""

"""
9. PASSWORD RESET CONFIRM
POST /auth/password/reset/confirm/
Content-Type: application/json

{
    "email": "buyer@example.com",
    "otp_code": "654321",
    "new_password": "resetpassword789",
    "new_password_confirm": "resetpassword789"
}

Response:
{
    "message": "Password reset successful. Please login with your new password."
}
"""

"""
10. RESEND OTP
POST /auth/email/resend-otp/
Content-Type: application/json

{
    "email": "buyer@example.com",
    "purpose": "verification"
}

Response:
{
    "message": "New verification code sent to your email",
    "email_sent": true
}
"""

"""
11. GET USER STATUS
GET /auth/status/
Postmen: Authorization -> Auth Type: API KEY(NOT "Bearer Token") 

Fill in the fields:

Key: Authorization
Value: Token abc123token
Add to: Header

Response:
{
    "user_id": 1,
    "email": "buyer@example.com",
    "user_type": "buyer",
    "is_verified": true,
    "is_active": true,
    "date_joined": "2024-01-15T10:00:00Z"
}
"""

"""
12. LOGOUT
POST /auth/logout/
Authorization: Token abc123token

Response:
{
    "message": "Logout successful"
}
"""

# JAVASCRIPT/FRONTEND INTEGRATION EXAMPLES

"""
// Example React/JavaScript integration

// 1. Registration function
async function registerBuyer(userData) {
    const response = await fetch('/auth/buyer/register/', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify(userData)
    });
    
    const data = await response.json();
    
    if (response.ok) {
        // Store token
        localStorage.setItem('authToken', data.token);
        localStorage.setItem('userType', 'buyer');
        return data;
    } else {
        throw new Error(data.error || 'Registration failed');
    }
}

// 2. Login function
async function login(email, password) {
    const response = await fetch('/auth/login/', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({ email, password })
    });
    
    const data = await response.json();
    
    if (response.ok) {
        localStorage.setItem('authToken', data.token);
        localStorage.setItem('userType', data.user_type);
        localStorage.setItem('userId', data.user_id);
        return data;
    } else {
        throw new Error(data.error || 'Login failed');
    }
}

// 3. Authenticated request function
async function makeAuthenticatedRequest(url, options = {}) {
    const token = localStorage.getItem('authToken');
    
    const defaultOptions = {
        headers: {
            'Content-Type': 'application/json',
            'Authorization': `Token ${token}`
        }
    };
    
    const mergedOptions = {
        ...defaultOptions,
        ...options,
        headers: {
            ...defaultOptions.headers,
            ...options.headers
        }
    };
    
    const response = await fetch(url, mergedOptions);
    
    if (response.status === 401) {
        // Token expired or invalid
        localStorage.removeItem('authToken');
        localStorage.removeItem('userType');
        localStorage.removeItem('userId');
        window.location.href = '/login';
        return;
    }
    
    return response;
}

// 4. Get user profile
async function getUserProfile() {
    const response = await makeAuthenticatedRequest('/auth/profile/');
    
    if (response.ok) {
        return await response.json();
    } else {
        throw new Error('Failed to fetch profile');
    }
}

// 5. Verify email
async function verifyEmail(email, otpCode) {
    const response = await fetch('/auth/email/verify/', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({
            email: email,
            otp_code: otpCode
        })
    });
    
    const data = await response.json();
    
    if (response.ok) {
        return data;
    } else {
        throw new Error(data.error || 'Email verification failed');
    }
}

// 6. Logout function
async function logout() {
    const response = await makeAuthenticatedRequest('/auth/logout/', {
        method: 'POST'
    });
    
    // Clear local storage regardless of response
    localStorage.removeItem('authToken');
    localStorage.removeItem('userType');
    localStorage.removeItem('userId');
    
    window.location.href = '/login';
}
"""

# ERROR HANDLING EXAMPLES

"""
Common Error Responses:

1. Validation Errors (400):
{
    "email": ["This field is required."],
    "password": ["This password is too short."]
}

2. Authentication Errors (401):
{
    "detail": "Invalid token."
}

3. Permission Errors (403):
{
    "detail": "You do not have permission to perform this action."
}

4. Not Found Errors (404):
{
    "detail": "Not found."
}

5. Server Errors (500):
{
    "detail": "Internal server error."
}
"""