// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Contains the authentication configuration details for a data accessor. This structure defines how the ISV authenticates when accessing data through the data accessor.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DataAccessorAuthenticationDetail {
    /// <p>The type of authentication to use for the data accessor. This determines how the ISV authenticates when accessing data. You can use one of two authentication types:</p>
    /// <ul>
    /// <li>
    /// <p><code>AWS_IAM_IDC_TTI</code> - Authentication using IAM Identity Center Trusted Token Issuer (TTI). This authentication type allows the ISV to use a trusted token issuer to generate tokens for accessing the data.</p></li>
    /// <li>
    /// <p><code>AWS_IAM_IDC_AUTH_CODE</code> - Authentication using IAM Identity Center authorization code flow. This authentication type uses the standard OAuth 2.0 authorization code flow for authentication.</p></li>
    /// </ul>
    pub authentication_type: crate::types::DataAccessorAuthenticationType,
    /// <p>The specific authentication configuration based on the authentication type.</p>
    pub authentication_configuration: ::std::option::Option<crate::types::DataAccessorAuthenticationConfiguration>,
    /// <p>A list of external identifiers associated with this authentication configuration. These are used to correlate the data accessor with external systems.</p>
    pub external_ids: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl DataAccessorAuthenticationDetail {
    /// <p>The type of authentication to use for the data accessor. This determines how the ISV authenticates when accessing data. You can use one of two authentication types:</p>
    /// <ul>
    /// <li>
    /// <p><code>AWS_IAM_IDC_TTI</code> - Authentication using IAM Identity Center Trusted Token Issuer (TTI). This authentication type allows the ISV to use a trusted token issuer to generate tokens for accessing the data.</p></li>
    /// <li>
    /// <p><code>AWS_IAM_IDC_AUTH_CODE</code> - Authentication using IAM Identity Center authorization code flow. This authentication type uses the standard OAuth 2.0 authorization code flow for authentication.</p></li>
    /// </ul>
    pub fn authentication_type(&self) -> &crate::types::DataAccessorAuthenticationType {
        &self.authentication_type
    }
    /// <p>The specific authentication configuration based on the authentication type.</p>
    pub fn authentication_configuration(&self) -> ::std::option::Option<&crate::types::DataAccessorAuthenticationConfiguration> {
        self.authentication_configuration.as_ref()
    }
    /// <p>A list of external identifiers associated with this authentication configuration. These are used to correlate the data accessor with external systems.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.external_ids.is_none()`.
    pub fn external_ids(&self) -> &[::std::string::String] {
        self.external_ids.as_deref().unwrap_or_default()
    }
}
impl DataAccessorAuthenticationDetail {
    /// Creates a new builder-style object to manufacture [`DataAccessorAuthenticationDetail`](crate::types::DataAccessorAuthenticationDetail).
    pub fn builder() -> crate::types::builders::DataAccessorAuthenticationDetailBuilder {
        crate::types::builders::DataAccessorAuthenticationDetailBuilder::default()
    }
}

/// A builder for [`DataAccessorAuthenticationDetail`](crate::types::DataAccessorAuthenticationDetail).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DataAccessorAuthenticationDetailBuilder {
    pub(crate) authentication_type: ::std::option::Option<crate::types::DataAccessorAuthenticationType>,
    pub(crate) authentication_configuration: ::std::option::Option<crate::types::DataAccessorAuthenticationConfiguration>,
    pub(crate) external_ids: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl DataAccessorAuthenticationDetailBuilder {
    /// <p>The type of authentication to use for the data accessor. This determines how the ISV authenticates when accessing data. You can use one of two authentication types:</p>
    /// <ul>
    /// <li>
    /// <p><code>AWS_IAM_IDC_TTI</code> - Authentication using IAM Identity Center Trusted Token Issuer (TTI). This authentication type allows the ISV to use a trusted token issuer to generate tokens for accessing the data.</p></li>
    /// <li>
    /// <p><code>AWS_IAM_IDC_AUTH_CODE</code> - Authentication using IAM Identity Center authorization code flow. This authentication type uses the standard OAuth 2.0 authorization code flow for authentication.</p></li>
    /// </ul>
    /// This field is required.
    pub fn authentication_type(mut self, input: crate::types::DataAccessorAuthenticationType) -> Self {
        self.authentication_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The type of authentication to use for the data accessor. This determines how the ISV authenticates when accessing data. You can use one of two authentication types:</p>
    /// <ul>
    /// <li>
    /// <p><code>AWS_IAM_IDC_TTI</code> - Authentication using IAM Identity Center Trusted Token Issuer (TTI). This authentication type allows the ISV to use a trusted token issuer to generate tokens for accessing the data.</p></li>
    /// <li>
    /// <p><code>AWS_IAM_IDC_AUTH_CODE</code> - Authentication using IAM Identity Center authorization code flow. This authentication type uses the standard OAuth 2.0 authorization code flow for authentication.</p></li>
    /// </ul>
    pub fn set_authentication_type(mut self, input: ::std::option::Option<crate::types::DataAccessorAuthenticationType>) -> Self {
        self.authentication_type = input;
        self
    }
    /// <p>The type of authentication to use for the data accessor. This determines how the ISV authenticates when accessing data. You can use one of two authentication types:</p>
    /// <ul>
    /// <li>
    /// <p><code>AWS_IAM_IDC_TTI</code> - Authentication using IAM Identity Center Trusted Token Issuer (TTI). This authentication type allows the ISV to use a trusted token issuer to generate tokens for accessing the data.</p></li>
    /// <li>
    /// <p><code>AWS_IAM_IDC_AUTH_CODE</code> - Authentication using IAM Identity Center authorization code flow. This authentication type uses the standard OAuth 2.0 authorization code flow for authentication.</p></li>
    /// </ul>
    pub fn get_authentication_type(&self) -> &::std::option::Option<crate::types::DataAccessorAuthenticationType> {
        &self.authentication_type
    }
    /// <p>The specific authentication configuration based on the authentication type.</p>
    pub fn authentication_configuration(mut self, input: crate::types::DataAccessorAuthenticationConfiguration) -> Self {
        self.authentication_configuration = ::std::option::Option::Some(input);
        self
    }
    /// <p>The specific authentication configuration based on the authentication type.</p>
    pub fn set_authentication_configuration(mut self, input: ::std::option::Option<crate::types::DataAccessorAuthenticationConfiguration>) -> Self {
        self.authentication_configuration = input;
        self
    }
    /// <p>The specific authentication configuration based on the authentication type.</p>
    pub fn get_authentication_configuration(&self) -> &::std::option::Option<crate::types::DataAccessorAuthenticationConfiguration> {
        &self.authentication_configuration
    }
    /// Appends an item to `external_ids`.
    ///
    /// To override the contents of this collection use [`set_external_ids`](Self::set_external_ids).
    ///
    /// <p>A list of external identifiers associated with this authentication configuration. These are used to correlate the data accessor with external systems.</p>
    pub fn external_ids(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.external_ids.unwrap_or_default();
        v.push(input.into());
        self.external_ids = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of external identifiers associated with this authentication configuration. These are used to correlate the data accessor with external systems.</p>
    pub fn set_external_ids(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.external_ids = input;
        self
    }
    /// <p>A list of external identifiers associated with this authentication configuration. These are used to correlate the data accessor with external systems.</p>
    pub fn get_external_ids(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.external_ids
    }
    /// Consumes the builder and constructs a [`DataAccessorAuthenticationDetail`](crate::types::DataAccessorAuthenticationDetail).
    /// This method will fail if any of the following fields are not set:
    /// - [`authentication_type`](crate::types::builders::DataAccessorAuthenticationDetailBuilder::authentication_type)
    pub fn build(self) -> ::std::result::Result<crate::types::DataAccessorAuthenticationDetail, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::DataAccessorAuthenticationDetail {
            authentication_type: self.authentication_type.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "authentication_type",
                    "authentication_type was not specified but it is required when building DataAccessorAuthenticationDetail",
                )
            })?,
            authentication_configuration: self.authentication_configuration,
            external_ids: self.external_ids,
        })
    }
}
