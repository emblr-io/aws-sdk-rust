// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Represents the verification attributes of a single identity.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct IdentityVerificationAttributes {
    /// <p>The verification status of the identity: "Pending", "Success", "Failed", or "TemporaryFailure".</p>
    pub verification_status: crate::types::VerificationStatus,
    /// <p>The verification token for a domain identity. Null for email address identities.</p>
    pub verification_token: ::std::option::Option<::std::string::String>,
}
impl IdentityVerificationAttributes {
    /// <p>The verification status of the identity: "Pending", "Success", "Failed", or "TemporaryFailure".</p>
    pub fn verification_status(&self) -> &crate::types::VerificationStatus {
        &self.verification_status
    }
    /// <p>The verification token for a domain identity. Null for email address identities.</p>
    pub fn verification_token(&self) -> ::std::option::Option<&str> {
        self.verification_token.as_deref()
    }
}
impl IdentityVerificationAttributes {
    /// Creates a new builder-style object to manufacture [`IdentityVerificationAttributes`](crate::types::IdentityVerificationAttributes).
    pub fn builder() -> crate::types::builders::IdentityVerificationAttributesBuilder {
        crate::types::builders::IdentityVerificationAttributesBuilder::default()
    }
}

/// A builder for [`IdentityVerificationAttributes`](crate::types::IdentityVerificationAttributes).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct IdentityVerificationAttributesBuilder {
    pub(crate) verification_status: ::std::option::Option<crate::types::VerificationStatus>,
    pub(crate) verification_token: ::std::option::Option<::std::string::String>,
}
impl IdentityVerificationAttributesBuilder {
    /// <p>The verification status of the identity: "Pending", "Success", "Failed", or "TemporaryFailure".</p>
    /// This field is required.
    pub fn verification_status(mut self, input: crate::types::VerificationStatus) -> Self {
        self.verification_status = ::std::option::Option::Some(input);
        self
    }
    /// <p>The verification status of the identity: "Pending", "Success", "Failed", or "TemporaryFailure".</p>
    pub fn set_verification_status(mut self, input: ::std::option::Option<crate::types::VerificationStatus>) -> Self {
        self.verification_status = input;
        self
    }
    /// <p>The verification status of the identity: "Pending", "Success", "Failed", or "TemporaryFailure".</p>
    pub fn get_verification_status(&self) -> &::std::option::Option<crate::types::VerificationStatus> {
        &self.verification_status
    }
    /// <p>The verification token for a domain identity. Null for email address identities.</p>
    pub fn verification_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.verification_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The verification token for a domain identity. Null for email address identities.</p>
    pub fn set_verification_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.verification_token = input;
        self
    }
    /// <p>The verification token for a domain identity. Null for email address identities.</p>
    pub fn get_verification_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.verification_token
    }
    /// Consumes the builder and constructs a [`IdentityVerificationAttributes`](crate::types::IdentityVerificationAttributes).
    /// This method will fail if any of the following fields are not set:
    /// - [`verification_status`](crate::types::builders::IdentityVerificationAttributesBuilder::verification_status)
    pub fn build(self) -> ::std::result::Result<crate::types::IdentityVerificationAttributes, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::IdentityVerificationAttributes {
            verification_status: self.verification_status.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "verification_status",
                    "verification_status was not specified but it is required when building IdentityVerificationAttributes",
                )
            })?,
            verification_token: self.verification_token,
        })
    }
}
