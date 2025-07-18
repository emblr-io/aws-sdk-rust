// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Represents a request to return the Amazon SES verification status of a list of identities. For domain identities, this request also returns the verification token. For information about verifying identities with Amazon SES, see the <a href="https://docs.aws.amazon.com/ses/latest/dg/creating-identities.html">Amazon SES Developer Guide</a>.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetIdentityVerificationAttributesInput {
    /// <p>A list of identities.</p>
    pub identities: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl GetIdentityVerificationAttributesInput {
    /// <p>A list of identities.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.identities.is_none()`.
    pub fn identities(&self) -> &[::std::string::String] {
        self.identities.as_deref().unwrap_or_default()
    }
}
impl GetIdentityVerificationAttributesInput {
    /// Creates a new builder-style object to manufacture [`GetIdentityVerificationAttributesInput`](crate::operation::get_identity_verification_attributes::GetIdentityVerificationAttributesInput).
    pub fn builder() -> crate::operation::get_identity_verification_attributes::builders::GetIdentityVerificationAttributesInputBuilder {
        crate::operation::get_identity_verification_attributes::builders::GetIdentityVerificationAttributesInputBuilder::default()
    }
}

/// A builder for [`GetIdentityVerificationAttributesInput`](crate::operation::get_identity_verification_attributes::GetIdentityVerificationAttributesInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetIdentityVerificationAttributesInputBuilder {
    pub(crate) identities: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl GetIdentityVerificationAttributesInputBuilder {
    /// Appends an item to `identities`.
    ///
    /// To override the contents of this collection use [`set_identities`](Self::set_identities).
    ///
    /// <p>A list of identities.</p>
    pub fn identities(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.identities.unwrap_or_default();
        v.push(input.into());
        self.identities = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of identities.</p>
    pub fn set_identities(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.identities = input;
        self
    }
    /// <p>A list of identities.</p>
    pub fn get_identities(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.identities
    }
    /// Consumes the builder and constructs a [`GetIdentityVerificationAttributesInput`](crate::operation::get_identity_verification_attributes::GetIdentityVerificationAttributesInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::get_identity_verification_attributes::GetIdentityVerificationAttributesInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(
            crate::operation::get_identity_verification_attributes::GetIdentityVerificationAttributesInput { identities: self.identities },
        )
    }
}
