// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct EnableDelegatedAdminAccountInput {
    /// <p>The Amazon Web Services account ID of the Amazon Inspector delegated administrator.</p>
    pub delegated_admin_account_id: ::std::option::Option<::std::string::String>,
    /// <p>The idempotency token for the request.</p>
    pub client_token: ::std::option::Option<::std::string::String>,
}
impl EnableDelegatedAdminAccountInput {
    /// <p>The Amazon Web Services account ID of the Amazon Inspector delegated administrator.</p>
    pub fn delegated_admin_account_id(&self) -> ::std::option::Option<&str> {
        self.delegated_admin_account_id.as_deref()
    }
    /// <p>The idempotency token for the request.</p>
    pub fn client_token(&self) -> ::std::option::Option<&str> {
        self.client_token.as_deref()
    }
}
impl EnableDelegatedAdminAccountInput {
    /// Creates a new builder-style object to manufacture [`EnableDelegatedAdminAccountInput`](crate::operation::enable_delegated_admin_account::EnableDelegatedAdminAccountInput).
    pub fn builder() -> crate::operation::enable_delegated_admin_account::builders::EnableDelegatedAdminAccountInputBuilder {
        crate::operation::enable_delegated_admin_account::builders::EnableDelegatedAdminAccountInputBuilder::default()
    }
}

/// A builder for [`EnableDelegatedAdminAccountInput`](crate::operation::enable_delegated_admin_account::EnableDelegatedAdminAccountInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct EnableDelegatedAdminAccountInputBuilder {
    pub(crate) delegated_admin_account_id: ::std::option::Option<::std::string::String>,
    pub(crate) client_token: ::std::option::Option<::std::string::String>,
}
impl EnableDelegatedAdminAccountInputBuilder {
    /// <p>The Amazon Web Services account ID of the Amazon Inspector delegated administrator.</p>
    /// This field is required.
    pub fn delegated_admin_account_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.delegated_admin_account_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Web Services account ID of the Amazon Inspector delegated administrator.</p>
    pub fn set_delegated_admin_account_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.delegated_admin_account_id = input;
        self
    }
    /// <p>The Amazon Web Services account ID of the Amazon Inspector delegated administrator.</p>
    pub fn get_delegated_admin_account_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.delegated_admin_account_id
    }
    /// <p>The idempotency token for the request.</p>
    pub fn client_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.client_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The idempotency token for the request.</p>
    pub fn set_client_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.client_token = input;
        self
    }
    /// <p>The idempotency token for the request.</p>
    pub fn get_client_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.client_token
    }
    /// Consumes the builder and constructs a [`EnableDelegatedAdminAccountInput`](crate::operation::enable_delegated_admin_account::EnableDelegatedAdminAccountInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::enable_delegated_admin_account::EnableDelegatedAdminAccountInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::enable_delegated_admin_account::EnableDelegatedAdminAccountInput {
            delegated_admin_account_id: self.delegated_admin_account_id,
            client_token: self.client_token,
        })
    }
}
