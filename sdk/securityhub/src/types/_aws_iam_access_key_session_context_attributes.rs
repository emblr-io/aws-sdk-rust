// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Attributes of the session that the key was used for.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AwsIamAccessKeySessionContextAttributes {
    /// <p>Indicates whether the session used multi-factor authentication (MFA).</p>
    pub mfa_authenticated: ::std::option::Option<bool>,
    /// <p>Indicates when the session was created.</p>
    /// <p>For more information about the validation and formatting of timestamp fields in Security Hub, see <a href="https://docs.aws.amazon.com/securityhub/1.0/APIReference/Welcome.html#timestamps">Timestamps</a>.</p>
    pub creation_date: ::std::option::Option<::std::string::String>,
}
impl AwsIamAccessKeySessionContextAttributes {
    /// <p>Indicates whether the session used multi-factor authentication (MFA).</p>
    pub fn mfa_authenticated(&self) -> ::std::option::Option<bool> {
        self.mfa_authenticated
    }
    /// <p>Indicates when the session was created.</p>
    /// <p>For more information about the validation and formatting of timestamp fields in Security Hub, see <a href="https://docs.aws.amazon.com/securityhub/1.0/APIReference/Welcome.html#timestamps">Timestamps</a>.</p>
    pub fn creation_date(&self) -> ::std::option::Option<&str> {
        self.creation_date.as_deref()
    }
}
impl AwsIamAccessKeySessionContextAttributes {
    /// Creates a new builder-style object to manufacture [`AwsIamAccessKeySessionContextAttributes`](crate::types::AwsIamAccessKeySessionContextAttributes).
    pub fn builder() -> crate::types::builders::AwsIamAccessKeySessionContextAttributesBuilder {
        crate::types::builders::AwsIamAccessKeySessionContextAttributesBuilder::default()
    }
}

/// A builder for [`AwsIamAccessKeySessionContextAttributes`](crate::types::AwsIamAccessKeySessionContextAttributes).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AwsIamAccessKeySessionContextAttributesBuilder {
    pub(crate) mfa_authenticated: ::std::option::Option<bool>,
    pub(crate) creation_date: ::std::option::Option<::std::string::String>,
}
impl AwsIamAccessKeySessionContextAttributesBuilder {
    /// <p>Indicates whether the session used multi-factor authentication (MFA).</p>
    pub fn mfa_authenticated(mut self, input: bool) -> Self {
        self.mfa_authenticated = ::std::option::Option::Some(input);
        self
    }
    /// <p>Indicates whether the session used multi-factor authentication (MFA).</p>
    pub fn set_mfa_authenticated(mut self, input: ::std::option::Option<bool>) -> Self {
        self.mfa_authenticated = input;
        self
    }
    /// <p>Indicates whether the session used multi-factor authentication (MFA).</p>
    pub fn get_mfa_authenticated(&self) -> &::std::option::Option<bool> {
        &self.mfa_authenticated
    }
    /// <p>Indicates when the session was created.</p>
    /// <p>For more information about the validation and formatting of timestamp fields in Security Hub, see <a href="https://docs.aws.amazon.com/securityhub/1.0/APIReference/Welcome.html#timestamps">Timestamps</a>.</p>
    pub fn creation_date(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.creation_date = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Indicates when the session was created.</p>
    /// <p>For more information about the validation and formatting of timestamp fields in Security Hub, see <a href="https://docs.aws.amazon.com/securityhub/1.0/APIReference/Welcome.html#timestamps">Timestamps</a>.</p>
    pub fn set_creation_date(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.creation_date = input;
        self
    }
    /// <p>Indicates when the session was created.</p>
    /// <p>For more information about the validation and formatting of timestamp fields in Security Hub, see <a href="https://docs.aws.amazon.com/securityhub/1.0/APIReference/Welcome.html#timestamps">Timestamps</a>.</p>
    pub fn get_creation_date(&self) -> &::std::option::Option<::std::string::String> {
        &self.creation_date
    }
    /// Consumes the builder and constructs a [`AwsIamAccessKeySessionContextAttributes`](crate::types::AwsIamAccessKeySessionContextAttributes).
    pub fn build(self) -> crate::types::AwsIamAccessKeySessionContextAttributes {
        crate::types::AwsIamAccessKeySessionContextAttributes {
            mfa_authenticated: self.mfa_authenticated,
            creation_date: self.creation_date,
        }
    }
}
