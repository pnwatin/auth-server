use auth_server::handlers::TokensResponse;
use reqwest::header::USER_AGENT;
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
async fn refresh_tokens_persists_refresh_token_metadata() {
    let app = TestApplication::spawn().await;

    app.sign_up().await;

    let sign_in_response = app.sign_in().await;

    let sign_in_tokens: TokensResponse = sign_in_response
        .json()
        .await
        .expect("Valid sign-in didn't return pair of tokens.");

    let user_agent = "user agent";

    app.post("/auth/tokens/refresh")
        .json(&json!({"refresh_token": sign_in_tokens.refresh_token}))
        .header(USER_AGENT, user_agent)
        .send()
        .await
        .expect("Failed to execute request.");

    let saved_refresh_token = sqlx::query!("SELECT * from refresh_tokens")
        .fetch_one(&app.pool)
        .await
        .expect("Failed to fetch new refresh_token");

    assert_eq!(saved_refresh_token.user_agent, Some(user_agent.to_string()));
    assert_eq!(
        saved_refresh_token.ip_address,
        Some(app.address.ip().to_string())
    );
}

#[tokio::test]
async fn refresh_tokens_with_used_refresh_token_invalids_token_family() {
    let app = TestApplication::spawn().await;

    app.sign_up().await;

    let sign_in_response = app.sign_in().await;

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
