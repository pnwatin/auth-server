use serde_json::json;

use crate::helpers::TestApplication;

#[tokio::test]
async fn sign_up_with_valid_data_returns_200() {
    let app = TestApplication::spawn().await;

    let response = app
        .post("/auth/sign-up")
        .json(&json!({
            "email": "test@gmail.com",
            "password": "password"
        }))
        .send()
        .await
        .expect("Failed to execute request.");

    assert_eq!(200, response.status().as_u16());
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
        let response = app
            .post("/auth/sign-up")
            .json(&invalid_body)
            .send()
            .await
            .expect("Failed to execute request.");

        assert_eq!(
            422,
            response.status().as_u16(),
            "/auth/sign-up did not return 422 when body was {}",
            error_message
        );
    }
}
