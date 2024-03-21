use crate::helpers::TestApplication;

#[tokio::test]
async fn health_check_works() {
    let app = TestApplication::spawn().await;

    let response = reqwest::Client::new()
        .get(format!("{}/_health-check", app.address))
        .send()
        .await
        .expect("Failed to execute request.");

    assert!(response.status().is_success());
    assert_eq!(Some(0), response.content_length());
}
