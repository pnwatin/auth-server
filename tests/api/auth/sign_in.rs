use auth_server::{
    handlers::{AccessToken, RefreshToken, Token, TokensResponse},
    settings::JWT_CONFIG,
};
use jsonwebtoken::Validation;
use serde_json::json;

use crate::helpers::TestApplication;

#[tokio::test]
async fn sign_in_with_valid_credentials_return_valid_tokens() {
    let app = TestApplication::spawn().await;

    let email = "test@domain.com";
    let password = "password";

    app.post("/auth/sign-up")
        .json(&json!({
        "email": email,
        "password": password
        }))
        .send()
        .await
        .expect("Failed to execute request.");

    let response = app
        .post("/auth/sign-in")
        .json(&json!({
            "email": email,
            "password": password
        }))
        .send()
        .await
        .expect("Failed to execute request.");

    assert_eq!(200, response.status().as_u16());

    let tokens: TokensResponse = response
        .json()
        .await
        .expect("Valid sign-in didn't return pair of tokens.");

    let access_token = AccessToken::decode(&tokens.access_token).expect("Access token is invalid.");

    let refresh_token =
        RefreshToken::decode(&tokens.refresh_token).expect("refresh token is invalid.");

    assert_eq!(access_token.iat, refresh_token.iat);
}

#[tokio::test]
async fn sign_in_with_valid_credentials_persists_refresh_token() {
    let app = TestApplication::spawn().await;

    let email = "test@domain.com";
    let password = "password";

    app.post("/auth/sign-up")
        .json(&json!({
        "email": email,
        "password": password
        }))
        .send()
        .await
        .expect("Failed to execute request.");

    let response = app
        .post("/auth/sign-in")
        .json(&json!({
            "email": email,
            "password": password
        }))
        .send()
        .await
        .expect("Failed to execute request.");

    assert_eq!(200, response.status().as_u16());

    let tokens: TokensResponse = response
        .json()
        .await
        .expect("Valid sign-in didn't return pair of tokens.");

    let refresh_token =
        RefreshToken::decode(&tokens.refresh_token).expect("refresh token is invalid.");

    let saved_refresh_token = sqlx::query!("SELECT * from refresh_tokens")
        .fetch_one(&app.pool)
        .await
        .expect("Failed to fetch new refresh_token");

    assert_eq!(saved_refresh_token.jit, refresh_token.jit);
}

#[tokio::test]
async fn sign_in_with_valid_credentials_return_tokens_that_expire() {
    let app = TestApplication::spawn().await;

    let email = "test@domain.com";
    let password = "password";

    app.post("/auth/sign-up")
        .json(&json!({
        "email": email,
        "password": password
        }))
        .send()
        .await
        .expect("Failed to execute request.");

    let response = app
        .post("/auth/sign-in")
        .json(&json!({
            "email": email,
            "password": password
        }))
        .send()
        .await
        .expect("Failed to execute request.");

    assert_eq!(200, response.status().as_u16());

    let tokens: TokensResponse = response
        .json()
        .await
        .expect("Valid sign-in didn't return pair of tokens.");

    let mut validation = Validation::default();
    validation.leeway = 0;

    tokio::time::sleep(std::time::Duration::from_secs(
        (JWT_CONFIG.access_token_exp_seconds as u64) + 1,
    ))
    .await;

    AccessToken::decode_with_validation(&tokens.access_token, &validation)
        .expect_err("Access token didn't expire.");

    RefreshToken::decode_with_validation(&tokens.refresh_token, &validation)
        .expect_err("Refresh token didn't expire.");
}

#[tokio::test]
async fn sign_in_with_valid_credentials_return_200() {
    let app = TestApplication::spawn().await;

    let email = "test@domain.com";
    let password = "password";

    app.post("/auth/sign-up")
        .json(&json!({
        "email": email,
        "password": password
        }))
        .send()
        .await
        .expect("Failed to execute request.");

    let response = app
        .post("/auth/sign-in")
        .json(&json!({
            "email": email,
            "password": password
        }))
        .send()
        .await
        .expect("Failed to execute request.");

    assert_eq!(200, response.status().as_u16());
}

#[tokio::test]
async fn sign_in_with_non_existing_email_return_401() {
    let app = TestApplication::spawn().await;

    let response = app
        .post("/auth/sign-in")
        .json(&json!({
            "email": "nonexisting@domain.com",
            "password": "password"
        }))
        .send()
        .await
        .expect("Failed to execute request.");

    assert_eq!(401, response.status().as_u16());
}

#[tokio::test]
async fn sign_in_with_non_invalid_password_return_401() {
    let app = TestApplication::spawn().await;

    let email = "test@domain.com";

    app.post("/auth/sign-up")
        .json(&json!({
        "email": email,
        "password": "correct-password"
        }))
        .send()
        .await
        .expect("Failed to execute request.");

    let response = app
        .post("/auth/sign-in")
        .json(&json!({
            "email": email,
            "password": "wrong-password"
        }))
        .send()
        .await
        .expect("Failed to execute request.");

    assert_eq!(401, response.status().as_u16());
}

#[tokio::test]
async fn sign_in_with_invalid_data_returns_422() {
    let app = TestApplication::spawn().await;

    let test_cases = vec![
        (json!({}), "missing data"),
        (json!({"password": "password"}), "missing email"),
        (json!({"email": "test@domain.com"}), "missing password"),
        (
            json!({"email": "testwrong@@gmail.com", "password": "password"}),
            "invalid email",
        ),
    ];

    for (invalid_body, error_message) in test_cases {
        let response = app
            .post("/auth/sign-in")
            .json(&invalid_body)
            .send()
            .await
            .expect("Failed to execute request.");

        assert_eq!(
            422,
            response.status().as_u16(),
            "/auth/sign-in did not return 422 when body was {}.",
            error_message
        );
    }
}
