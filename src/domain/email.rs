use validator::ValidateEmail;

#[derive(Debug)]
pub struct Email(String);

#[derive(Debug, thiserror::Error)]
pub enum ParseEmailError {
    #[error("invalid email address")]
    Invalid,
}

impl Email {
    pub fn parse(email_candidate: String) -> Result<Self, ParseEmailError> {
        if ValidateEmail::validate_email(&email_candidate) {
            Ok(Self(email_candidate))
        } else {
            Err(ParseEmailError::Invalid)
        }
    }
}

impl AsRef<str> for Email {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for Email {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

#[cfg(test)]
mod tests {
    use claim::assert_err;
    use fake::locales::{self, Data};

    use super::Email;

    #[derive(Debug, Clone)]
    struct ValidEmailFixture(pub String);

    impl quickcheck::Arbitrary for ValidEmailFixture {
        fn arbitrary(g: &mut quickcheck::Gen) -> Self {
            let username = g
                .choose(locales::EN::NAME_FIRST_NAME)
                .unwrap()
                .to_ascii_lowercase();

            let domain = g.choose(&["com", "net", "fr", "org"]).unwrap();
            let email = format!("{username}@example.{domain}");

            Self(email)
        }
    }

    #[quickcheck_macros::quickcheck]
    fn valid_emails_are_parsed_successfully(valid_email: ValidEmailFixture) -> bool {
        Email::parse(valid_email.0).is_ok()
    }

    #[test]
    fn empty_string_is_rejected() {
        let email = "".to_string();
        assert_err!(Email::parse(email));
    }

    #[test]
    fn email_missing_at_symbol_is_rejected() {
        let email = "ursuladomain.com".to_string();
        assert_err!(Email::parse(email));
    }
    #[test]
    fn email_missing_subject_is_rejected() {
        let email = "@domain.com".to_string();
        assert_err!(Email::parse(email));
    }
}
