use serde_with::DeserializeFromStr;
use validator::ValidateEmail;

#[derive(Debug, DeserializeFromStr)]
pub struct Email(String);

#[derive(Debug, thiserror::Error)]
pub enum ParseEmailError {
    #[error("invalid email address")]
    Invalid,
}

impl std::str::FromStr for Email {
    type Err = ParseEmailError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if ValidateEmail::validate_email(&s) {
            Ok(Self(s.to_string()))
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

    use super::{Email, ParseEmailError};

    fn parse_email(email_candidate: &str) -> Result<Email, ParseEmailError> {
        email_candidate.parse::<Email>()
    }

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
        parse_email(&valid_email.0).is_ok()
    }

    #[test]
    fn empty_string_is_rejected() {
        assert_err!(parse_email(""));
    }

    #[test]
    fn email_missing_at_symbol_is_rejected() {
        assert_err!(parse_email("testwithoutatdomain.com"));
    }
    #[test]
    fn email_missing_subject_is_rejected() {
        assert_err!(parse_email("@domain.com"));
    }
}
