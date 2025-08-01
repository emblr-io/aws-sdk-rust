// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The Amazon SageMaker Canvas application setting where you configure OAuth for connecting to an external data source, such as Snowflake.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct IdentityProviderOAuthSetting {
    /// <p>The name of the data source that you're connecting to. Canvas currently supports OAuth for Snowflake and Salesforce Data Cloud.</p>
    pub data_source_name: ::std::option::Option<crate::types::DataSourceName>,
    /// <p>Describes whether OAuth for a data source is enabled or disabled in the Canvas application.</p>
    pub status: ::std::option::Option<crate::types::FeatureStatus>,
    /// <p>The ARN of an Amazon Web Services Secrets Manager secret that stores the credentials from your identity provider, such as the client ID and secret, authorization URL, and token URL.</p>
    pub secret_arn: ::std::option::Option<::std::string::String>,
}
impl IdentityProviderOAuthSetting {
    /// <p>The name of the data source that you're connecting to. Canvas currently supports OAuth for Snowflake and Salesforce Data Cloud.</p>
    pub fn data_source_name(&self) -> ::std::option::Option<&crate::types::DataSourceName> {
        self.data_source_name.as_ref()
    }
    /// <p>Describes whether OAuth for a data source is enabled or disabled in the Canvas application.</p>
    pub fn status(&self) -> ::std::option::Option<&crate::types::FeatureStatus> {
        self.status.as_ref()
    }
    /// <p>The ARN of an Amazon Web Services Secrets Manager secret that stores the credentials from your identity provider, such as the client ID and secret, authorization URL, and token URL.</p>
    pub fn secret_arn(&self) -> ::std::option::Option<&str> {
        self.secret_arn.as_deref()
    }
}
impl IdentityProviderOAuthSetting {
    /// Creates a new builder-style object to manufacture [`IdentityProviderOAuthSetting`](crate::types::IdentityProviderOAuthSetting).
    pub fn builder() -> crate::types::builders::IdentityProviderOAuthSettingBuilder {
        crate::types::builders::IdentityProviderOAuthSettingBuilder::default()
    }
}

/// A builder for [`IdentityProviderOAuthSetting`](crate::types::IdentityProviderOAuthSetting).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct IdentityProviderOAuthSettingBuilder {
    pub(crate) data_source_name: ::std::option::Option<crate::types::DataSourceName>,
    pub(crate) status: ::std::option::Option<crate::types::FeatureStatus>,
    pub(crate) secret_arn: ::std::option::Option<::std::string::String>,
}
impl IdentityProviderOAuthSettingBuilder {
    /// <p>The name of the data source that you're connecting to. Canvas currently supports OAuth for Snowflake and Salesforce Data Cloud.</p>
    pub fn data_source_name(mut self, input: crate::types::DataSourceName) -> Self {
        self.data_source_name = ::std::option::Option::Some(input);
        self
    }
    /// <p>The name of the data source that you're connecting to. Canvas currently supports OAuth for Snowflake and Salesforce Data Cloud.</p>
    pub fn set_data_source_name(mut self, input: ::std::option::Option<crate::types::DataSourceName>) -> Self {
        self.data_source_name = input;
        self
    }
    /// <p>The name of the data source that you're connecting to. Canvas currently supports OAuth for Snowflake and Salesforce Data Cloud.</p>
    pub fn get_data_source_name(&self) -> &::std::option::Option<crate::types::DataSourceName> {
        &self.data_source_name
    }
    /// <p>Describes whether OAuth for a data source is enabled or disabled in the Canvas application.</p>
    pub fn status(mut self, input: crate::types::FeatureStatus) -> Self {
        self.status = ::std::option::Option::Some(input);
        self
    }
    /// <p>Describes whether OAuth for a data source is enabled or disabled in the Canvas application.</p>
    pub fn set_status(mut self, input: ::std::option::Option<crate::types::FeatureStatus>) -> Self {
        self.status = input;
        self
    }
    /// <p>Describes whether OAuth for a data source is enabled or disabled in the Canvas application.</p>
    pub fn get_status(&self) -> &::std::option::Option<crate::types::FeatureStatus> {
        &self.status
    }
    /// <p>The ARN of an Amazon Web Services Secrets Manager secret that stores the credentials from your identity provider, such as the client ID and secret, authorization URL, and token URL.</p>
    pub fn secret_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.secret_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ARN of an Amazon Web Services Secrets Manager secret that stores the credentials from your identity provider, such as the client ID and secret, authorization URL, and token URL.</p>
    pub fn set_secret_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.secret_arn = input;
        self
    }
    /// <p>The ARN of an Amazon Web Services Secrets Manager secret that stores the credentials from your identity provider, such as the client ID and secret, authorization URL, and token URL.</p>
    pub fn get_secret_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.secret_arn
    }
    /// Consumes the builder and constructs a [`IdentityProviderOAuthSetting`](crate::types::IdentityProviderOAuthSetting).
    pub fn build(self) -> crate::types::IdentityProviderOAuthSetting {
        crate::types::IdentityProviderOAuthSetting {
            data_source_name: self.data_source_name,
            status: self.status,
            secret_arn: self.secret_arn,
        }
    }
}
