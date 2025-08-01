// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq)]
pub struct GetChallengePasswordOutput {
    /// <p>The SCEP challenge password.</p>
    pub password: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl GetChallengePasswordOutput {
    /// <p>The SCEP challenge password.</p>
    pub fn password(&self) -> ::std::option::Option<&str> {
        self.password.as_deref()
    }
}
impl ::std::fmt::Debug for GetChallengePasswordOutput {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("GetChallengePasswordOutput");
        formatter.field("password", &"*** Sensitive Data Redacted ***");
        formatter.field("_request_id", &self._request_id);
        formatter.finish()
    }
}
impl ::aws_types::request_id::RequestId for GetChallengePasswordOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl GetChallengePasswordOutput {
    /// Creates a new builder-style object to manufacture [`GetChallengePasswordOutput`](crate::operation::get_challenge_password::GetChallengePasswordOutput).
    pub fn builder() -> crate::operation::get_challenge_password::builders::GetChallengePasswordOutputBuilder {
        crate::operation::get_challenge_password::builders::GetChallengePasswordOutputBuilder::default()
    }
}

/// A builder for [`GetChallengePasswordOutput`](crate::operation::get_challenge_password::GetChallengePasswordOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default)]
#[non_exhaustive]
pub struct GetChallengePasswordOutputBuilder {
    pub(crate) password: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl GetChallengePasswordOutputBuilder {
    /// <p>The SCEP challenge password.</p>
    pub fn password(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.password = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The SCEP challenge password.</p>
    pub fn set_password(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.password = input;
        self
    }
    /// <p>The SCEP challenge password.</p>
    pub fn get_password(&self) -> &::std::option::Option<::std::string::String> {
        &self.password
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`GetChallengePasswordOutput`](crate::operation::get_challenge_password::GetChallengePasswordOutput).
    pub fn build(self) -> crate::operation::get_challenge_password::GetChallengePasswordOutput {
        crate::operation::get_challenge_password::GetChallengePasswordOutput {
            password: self.password,
            _request_id: self._request_id,
        }
    }
}
impl ::std::fmt::Debug for GetChallengePasswordOutputBuilder {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("GetChallengePasswordOutputBuilder");
        formatter.field("password", &"*** Sensitive Data Redacted ***");
        formatter.field("_request_id", &self._request_id);
        formatter.finish()
    }
}
