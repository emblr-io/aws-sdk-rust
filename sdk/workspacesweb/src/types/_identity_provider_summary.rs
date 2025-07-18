// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The summary of the identity provider.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq)]
pub struct IdentityProviderSummary {
    /// <p>The ARN of the identity provider.</p>
    pub identity_provider_arn: ::std::string::String,
    /// <p>The identity provider name.</p>
    pub identity_provider_name: ::std::option::Option<::std::string::String>,
    /// <p>The identity provider type.</p>
    pub identity_provider_type: ::std::option::Option<crate::types::IdentityProviderType>,
}
impl IdentityProviderSummary {
    /// <p>The ARN of the identity provider.</p>
    pub fn identity_provider_arn(&self) -> &str {
        use std::ops::Deref;
        self.identity_provider_arn.deref()
    }
    /// <p>The identity provider name.</p>
    pub fn identity_provider_name(&self) -> ::std::option::Option<&str> {
        self.identity_provider_name.as_deref()
    }
    /// <p>The identity provider type.</p>
    pub fn identity_provider_type(&self) -> ::std::option::Option<&crate::types::IdentityProviderType> {
        self.identity_provider_type.as_ref()
    }
}
impl ::std::fmt::Debug for IdentityProviderSummary {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("IdentityProviderSummary");
        formatter.field("identity_provider_arn", &self.identity_provider_arn);
        formatter.field("identity_provider_name", &"*** Sensitive Data Redacted ***");
        formatter.field("identity_provider_type", &self.identity_provider_type);
        formatter.finish()
    }
}
impl IdentityProviderSummary {
    /// Creates a new builder-style object to manufacture [`IdentityProviderSummary`](crate::types::IdentityProviderSummary).
    pub fn builder() -> crate::types::builders::IdentityProviderSummaryBuilder {
        crate::types::builders::IdentityProviderSummaryBuilder::default()
    }
}

/// A builder for [`IdentityProviderSummary`](crate::types::IdentityProviderSummary).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default)]
#[non_exhaustive]
pub struct IdentityProviderSummaryBuilder {
    pub(crate) identity_provider_arn: ::std::option::Option<::std::string::String>,
    pub(crate) identity_provider_name: ::std::option::Option<::std::string::String>,
    pub(crate) identity_provider_type: ::std::option::Option<crate::types::IdentityProviderType>,
}
impl IdentityProviderSummaryBuilder {
    /// <p>The ARN of the identity provider.</p>
    /// This field is required.
    pub fn identity_provider_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.identity_provider_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ARN of the identity provider.</p>
    pub fn set_identity_provider_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.identity_provider_arn = input;
        self
    }
    /// <p>The ARN of the identity provider.</p>
    pub fn get_identity_provider_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.identity_provider_arn
    }
    /// <p>The identity provider name.</p>
    pub fn identity_provider_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.identity_provider_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identity provider name.</p>
    pub fn set_identity_provider_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.identity_provider_name = input;
        self
    }
    /// <p>The identity provider name.</p>
    pub fn get_identity_provider_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.identity_provider_name
    }
    /// <p>The identity provider type.</p>
    pub fn identity_provider_type(mut self, input: crate::types::IdentityProviderType) -> Self {
        self.identity_provider_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The identity provider type.</p>
    pub fn set_identity_provider_type(mut self, input: ::std::option::Option<crate::types::IdentityProviderType>) -> Self {
        self.identity_provider_type = input;
        self
    }
    /// <p>The identity provider type.</p>
    pub fn get_identity_provider_type(&self) -> &::std::option::Option<crate::types::IdentityProviderType> {
        &self.identity_provider_type
    }
    /// Consumes the builder and constructs a [`IdentityProviderSummary`](crate::types::IdentityProviderSummary).
    /// This method will fail if any of the following fields are not set:
    /// - [`identity_provider_arn`](crate::types::builders::IdentityProviderSummaryBuilder::identity_provider_arn)
    pub fn build(self) -> ::std::result::Result<crate::types::IdentityProviderSummary, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::IdentityProviderSummary {
            identity_provider_arn: self.identity_provider_arn.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "identity_provider_arn",
                    "identity_provider_arn was not specified but it is required when building IdentityProviderSummary",
                )
            })?,
            identity_provider_name: self.identity_provider_name,
            identity_provider_type: self.identity_provider_type,
        })
    }
}
impl ::std::fmt::Debug for IdentityProviderSummaryBuilder {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("IdentityProviderSummaryBuilder");
        formatter.field("identity_provider_arn", &self.identity_provider_arn);
        formatter.field("identity_provider_name", &"*** Sensitive Data Redacted ***");
        formatter.field("identity_provider_type", &self.identity_provider_type);
        formatter.finish()
    }
}
