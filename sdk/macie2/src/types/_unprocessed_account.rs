// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Provides information about an account-related request that hasn't been processed.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UnprocessedAccount {
    /// <p>The Amazon Web Services account ID for the account that the request applies to.</p>
    pub account_id: ::std::option::Option<::std::string::String>,
    /// <p>The source of the issue or delay in processing the request.</p>
    pub error_code: ::std::option::Option<crate::types::ErrorCode>,
    /// <p>The reason why the request hasn't been processed.</p>
    pub error_message: ::std::option::Option<::std::string::String>,
}
impl UnprocessedAccount {
    /// <p>The Amazon Web Services account ID for the account that the request applies to.</p>
    pub fn account_id(&self) -> ::std::option::Option<&str> {
        self.account_id.as_deref()
    }
    /// <p>The source of the issue or delay in processing the request.</p>
    pub fn error_code(&self) -> ::std::option::Option<&crate::types::ErrorCode> {
        self.error_code.as_ref()
    }
    /// <p>The reason why the request hasn't been processed.</p>
    pub fn error_message(&self) -> ::std::option::Option<&str> {
        self.error_message.as_deref()
    }
}
impl UnprocessedAccount {
    /// Creates a new builder-style object to manufacture [`UnprocessedAccount`](crate::types::UnprocessedAccount).
    pub fn builder() -> crate::types::builders::UnprocessedAccountBuilder {
        crate::types::builders::UnprocessedAccountBuilder::default()
    }
}

/// A builder for [`UnprocessedAccount`](crate::types::UnprocessedAccount).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UnprocessedAccountBuilder {
    pub(crate) account_id: ::std::option::Option<::std::string::String>,
    pub(crate) error_code: ::std::option::Option<crate::types::ErrorCode>,
    pub(crate) error_message: ::std::option::Option<::std::string::String>,
}
impl UnprocessedAccountBuilder {
    /// <p>The Amazon Web Services account ID for the account that the request applies to.</p>
    pub fn account_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.account_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Web Services account ID for the account that the request applies to.</p>
    pub fn set_account_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.account_id = input;
        self
    }
    /// <p>The Amazon Web Services account ID for the account that the request applies to.</p>
    pub fn get_account_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.account_id
    }
    /// <p>The source of the issue or delay in processing the request.</p>
    pub fn error_code(mut self, input: crate::types::ErrorCode) -> Self {
        self.error_code = ::std::option::Option::Some(input);
        self
    }
    /// <p>The source of the issue or delay in processing the request.</p>
    pub fn set_error_code(mut self, input: ::std::option::Option<crate::types::ErrorCode>) -> Self {
        self.error_code = input;
        self
    }
    /// <p>The source of the issue or delay in processing the request.</p>
    pub fn get_error_code(&self) -> &::std::option::Option<crate::types::ErrorCode> {
        &self.error_code
    }
    /// <p>The reason why the request hasn't been processed.</p>
    pub fn error_message(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.error_message = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The reason why the request hasn't been processed.</p>
    pub fn set_error_message(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.error_message = input;
        self
    }
    /// <p>The reason why the request hasn't been processed.</p>
    pub fn get_error_message(&self) -> &::std::option::Option<::std::string::String> {
        &self.error_message
    }
    /// Consumes the builder and constructs a [`UnprocessedAccount`](crate::types::UnprocessedAccount).
    pub fn build(self) -> crate::types::UnprocessedAccount {
        crate::types::UnprocessedAccount {
            account_id: self.account_id,
            error_code: self.error_code,
            error_message: self.error_message,
        }
    }
}
