// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq)]
pub struct StartWebAuthnRegistrationInput {
    /// <p>A valid access token that Amazon Cognito issued to the currently signed-in user. Must include a scope claim for <code>aws.cognito.signin.user.admin</code>.</p>
    pub access_token: ::std::option::Option<::std::string::String>,
}
impl StartWebAuthnRegistrationInput {
    /// <p>A valid access token that Amazon Cognito issued to the currently signed-in user. Must include a scope claim for <code>aws.cognito.signin.user.admin</code>.</p>
    pub fn access_token(&self) -> ::std::option::Option<&str> {
        self.access_token.as_deref()
    }
}
impl ::std::fmt::Debug for StartWebAuthnRegistrationInput {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("StartWebAuthnRegistrationInput");
        formatter.field("access_token", &"*** Sensitive Data Redacted ***");
        formatter.finish()
    }
}
impl StartWebAuthnRegistrationInput {
    /// Creates a new builder-style object to manufacture [`StartWebAuthnRegistrationInput`](crate::operation::start_web_authn_registration::StartWebAuthnRegistrationInput).
    pub fn builder() -> crate::operation::start_web_authn_registration::builders::StartWebAuthnRegistrationInputBuilder {
        crate::operation::start_web_authn_registration::builders::StartWebAuthnRegistrationInputBuilder::default()
    }
}

/// A builder for [`StartWebAuthnRegistrationInput`](crate::operation::start_web_authn_registration::StartWebAuthnRegistrationInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default)]
#[non_exhaustive]
pub struct StartWebAuthnRegistrationInputBuilder {
    pub(crate) access_token: ::std::option::Option<::std::string::String>,
}
impl StartWebAuthnRegistrationInputBuilder {
    /// <p>A valid access token that Amazon Cognito issued to the currently signed-in user. Must include a scope claim for <code>aws.cognito.signin.user.admin</code>.</p>
    /// This field is required.
    pub fn access_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.access_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A valid access token that Amazon Cognito issued to the currently signed-in user. Must include a scope claim for <code>aws.cognito.signin.user.admin</code>.</p>
    pub fn set_access_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.access_token = input;
        self
    }
    /// <p>A valid access token that Amazon Cognito issued to the currently signed-in user. Must include a scope claim for <code>aws.cognito.signin.user.admin</code>.</p>
    pub fn get_access_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.access_token
    }
    /// Consumes the builder and constructs a [`StartWebAuthnRegistrationInput`](crate::operation::start_web_authn_registration::StartWebAuthnRegistrationInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::start_web_authn_registration::StartWebAuthnRegistrationInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::start_web_authn_registration::StartWebAuthnRegistrationInput {
            access_token: self.access_token,
        })
    }
}
impl ::std::fmt::Debug for StartWebAuthnRegistrationInputBuilder {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("StartWebAuthnRegistrationInputBuilder");
        formatter.field("access_token", &"*** Sensitive Data Redacted ***");
        formatter.finish()
    }
}
