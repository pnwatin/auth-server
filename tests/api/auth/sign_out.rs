use auth_server::handlers::TokensResponse;
use serde_json::json;

use crate::helpers::TestApplication;

#[tokio::test]
async fn sign_out_without_refresh_token_returns_422() {
    let app = TestApplication::spawn().await;

    let response = app
        .post("/auth/sign-out")
        .json(&json!({}))
        .send()
        .await
        .expect("Failed to execute request.");

    assert_eq!(
        422,
        response.status().as_u16(),
        "/auth/sign-out did not return 422 when body was missing refresh_token",
    );
}

#[tokio::test]
async fn sign_out_invalidates_refresh_token() {
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

    app.post("/auth/sign-out")
        .json(&json!({
        "refresh_token": sign_in_tokens.refresh_token
        }))
        .send()
        .await
        .expect("Failed to execute request.");

    let response = app
        .post("/auth/tokens/refresh")
        .json(&json!({"refresh_token": sign_in_tokens.refresh_token}))
        .send()
        .await
        .expect("Failed to execute request.");

    assert_eq!(
        401,
        response.status().as_u16(),
        "/auth/sign-out did not invalidate refresh token.",
    );
}
