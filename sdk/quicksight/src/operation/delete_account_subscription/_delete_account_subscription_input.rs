// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteAccountSubscriptionInput {
    /// <p>The Amazon Web Services account ID of the account that you want to delete.</p>
    pub aws_account_id: ::std::option::Option<::std::string::String>,
}
impl DeleteAccountSubscriptionInput {
    /// <p>The Amazon Web Services account ID of the account that you want to delete.</p>
    pub fn aws_account_id(&self) -> ::std::option::Option<&str> {
        self.aws_account_id.as_deref()
    }
}
impl DeleteAccountSubscriptionInput {
    /// Creates a new builder-style object to manufacture [`DeleteAccountSubscriptionInput`](crate::operation::delete_account_subscription::DeleteAccountSubscriptionInput).
    pub fn builder() -> crate::operation::delete_account_subscription::builders::DeleteAccountSubscriptionInputBuilder {
        crate::operation::delete_account_subscription::builders::DeleteAccountSubscriptionInputBuilder::default()
    }
}

/// A builder for [`DeleteAccountSubscriptionInput`](crate::operation::delete_account_subscription::DeleteAccountSubscriptionInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeleteAccountSubscriptionInputBuilder {
    pub(crate) aws_account_id: ::std::option::Option<::std::string::String>,
}
impl DeleteAccountSubscriptionInputBuilder {
    /// <p>The Amazon Web Services account ID of the account that you want to delete.</p>
    /// This field is required.
    pub fn aws_account_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.aws_account_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Web Services account ID of the account that you want to delete.</p>
    pub fn set_aws_account_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.aws_account_id = input;
        self
    }
    /// <p>The Amazon Web Services account ID of the account that you want to delete.</p>
    pub fn get_aws_account_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.aws_account_id
    }
    /// Consumes the builder and constructs a [`DeleteAccountSubscriptionInput`](crate::operation::delete_account_subscription::DeleteAccountSubscriptionInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::delete_account_subscription::DeleteAccountSubscriptionInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::delete_account_subscription::DeleteAccountSubscriptionInput {
            aws_account_id: self.aws_account_id,
        })
    }
}
