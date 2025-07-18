// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A request to return the policies of an email identity.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetEmailIdentityPoliciesInput {
    /// <p>The email identity.</p>
    pub email_identity: ::std::option::Option<::std::string::String>,
}
impl GetEmailIdentityPoliciesInput {
    /// <p>The email identity.</p>
    pub fn email_identity(&self) -> ::std::option::Option<&str> {
        self.email_identity.as_deref()
    }
}
impl GetEmailIdentityPoliciesInput {
    /// Creates a new builder-style object to manufacture [`GetEmailIdentityPoliciesInput`](crate::operation::get_email_identity_policies::GetEmailIdentityPoliciesInput).
    pub fn builder() -> crate::operation::get_email_identity_policies::builders::GetEmailIdentityPoliciesInputBuilder {
        crate::operation::get_email_identity_policies::builders::GetEmailIdentityPoliciesInputBuilder::default()
    }
}

/// A builder for [`GetEmailIdentityPoliciesInput`](crate::operation::get_email_identity_policies::GetEmailIdentityPoliciesInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetEmailIdentityPoliciesInputBuilder {
    pub(crate) email_identity: ::std::option::Option<::std::string::String>,
}
impl GetEmailIdentityPoliciesInputBuilder {
    /// <p>The email identity.</p>
    /// This field is required.
    pub fn email_identity(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.email_identity = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The email identity.</p>
    pub fn set_email_identity(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.email_identity = input;
        self
    }
    /// <p>The email identity.</p>
    pub fn get_email_identity(&self) -> &::std::option::Option<::std::string::String> {
        &self.email_identity
    }
    /// Consumes the builder and constructs a [`GetEmailIdentityPoliciesInput`](crate::operation::get_email_identity_policies::GetEmailIdentityPoliciesInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::get_email_identity_policies::GetEmailIdentityPoliciesInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::get_email_identity_policies::GetEmailIdentityPoliciesInput {
            email_identity: self.email_identity,
        })
    }
}
