use matoscout_api::handlers::TokensResponse;
use serde_json::json;

use crate::helpers::TestApplication;

#[tokio::test]
async fn refresh_tokens_without_refresh_token_returns_422() {
    let app = TestApplication::spawn().await;

    let response = app
        .post("/auth/tokens/refresh")
        .json(&json!({}))
        .send()
        .await
        .expect("Failed to execute request.");

    assert_eq!(
        422,
        response.status().as_u16(),
        "/auth/tokens/refresh did not return 422 when body was missing refresh_token",
    );
}

#[tokio::test]
async fn refresh_tokens_with_invalid_refresh_token_returns_401() {
    let app = TestApplication::spawn().await;

    let response = app
        .post("/auth/tokens/refresh")
        .json(&json!({"refresh_token": "invalid-token"}))
        .send()
        .await
        .expect("Failed to execute request.");

    assert_eq!(
        401,
        response.status().as_u16(),
        "/auth/tokens/refresh did not return 401 when body was invalid refresh_token",
    );
}

#[tokio::test]
async fn refresh_tokens_with_used_refresh_token_invalids_token_family() {
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

    let sign_in_response = app
        .post("/auth/sign-in")
        .json(&json!({
            "email": email,
            "password": password
        }))
        .send()
        .await
        .expect("Failed to execute request.");

    assert_eq!(200, sign_in_response.status().as_u16());

    let sign_in_tokens: TokensResponse = sign_in_response
        .json()
        .await
        .expect("Valid sign-in didn't return pair of tokens.");

    let legitimate_response = app
        .post("/auth/tokens/refresh")
        .json(&json!({"refresh_token": sign_in_tokens.refresh_token}))
        .send()
        .await
        .expect("Failed to execute request.");

    app.post("/auth/tokens/refresh")
        .json(&json!({"refresh_token": sign_in_tokens.refresh_token}))
        .send()
        .await
        .expect("Failed to execute request.");

    let tokens: TokensResponse = legitimate_response
        .json()
        .await
        .expect("Valid sign-in didn't return pair of tokens.");

    let response = app
        .post("/auth/tokens/refresh")
        .json(&json!({"refresh_token": tokens.refresh_token}))
        .send()
        .await
        .expect("Failed to execute request.");

    assert_eq!(
        401,
        response.status().as_u16(),
        "/auth/tokens/refresh did not return 401 when body was used refresh_token",
    );
}
