use serde_json::json;

use crate::helpers::TestApplication;

#[tokio::test]
async fn sign_up_with_valid_data_persists_user() {
    let app = TestApplication::spawn().await;

    app.sign_up()
        .await
        .error_for_status()
        .expect("Failed sign-up");

    let saved_user = sqlx::query!("SELECT email FROM users;")
        .fetch_one(&app.pool)
        .await
        .expect("Failed to fetch new user.");

    assert_eq!(saved_user.email, app.test_user.email);
}

#[tokio::test]
async fn sign_up_with_existing_email_returns_409() {
    let app = TestApplication::spawn().await;

    let _ = app
        .sign_up()
        .await
        .error_for_status()
        .expect("Failed sign-up");

    let response = app.sign_up().await;

    assert_eq!(
        409,
        response.status().as_u16(),
        "/auth/sign-up did not return 409 when email is already taken."
    )
}

#[tokio::test]
async fn sign_up_with_invalid_data_returns_422() {
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
        let response = app.sign_up_with_payload(&invalid_body).await;

        assert_eq!(
            422,
            response.status().as_u16(),
            "/auth/sign-up did not return 422 when body was {}",
            error_message
        );
    }
}
