// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The connector-specific profile properties required when using SAPOData.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct SapoDataConnectorProfileProperties {
    /// <p>The location of the SAPOData resource.</p>
    pub application_host_url: ::std::string::String,
    /// <p>The application path to catalog service.</p>
    pub application_service_path: ::std::string::String,
    /// <p>The port number of the SAPOData instance.</p>
    pub port_number: i32,
    /// <p>The client number for the client creating the connection.</p>
    pub client_number: ::std::string::String,
    /// <p>The logon language of SAPOData instance.</p>
    pub logon_language: ::std::option::Option<::std::string::String>,
    /// <p>The SAPOData Private Link service name to be used for private data transfers.</p>
    pub private_link_service_name: ::std::option::Option<::std::string::String>,
    /// <p>The SAPOData OAuth properties required for OAuth type authentication.</p>
    pub o_auth_properties: ::std::option::Option<crate::types::OAuthProperties>,
    /// <p>If you set this parameter to <code>true</code>, Amazon AppFlow bypasses the single sign-on (SSO) settings in your SAP account when it accesses your SAP OData instance.</p>
    /// <p>Whether you need this option depends on the types of credentials that you applied to your SAP OData connection profile. If your profile uses basic authentication credentials, SAP SSO can prevent Amazon AppFlow from connecting to your account with your username and password. In this case, bypassing SSO makes it possible for Amazon AppFlow to connect successfully. However, if your profile uses OAuth credentials, this parameter has no affect.</p>
    pub disable_sso: bool,
}
impl SapoDataConnectorProfileProperties {
    /// <p>The location of the SAPOData resource.</p>
    pub fn application_host_url(&self) -> &str {
        use std::ops::Deref;
        self.application_host_url.deref()
    }
    /// <p>The application path to catalog service.</p>
    pub fn application_service_path(&self) -> &str {
        use std::ops::Deref;
        self.application_service_path.deref()
    }
    /// <p>The port number of the SAPOData instance.</p>
    pub fn port_number(&self) -> i32 {
        self.port_number
    }
    /// <p>The client number for the client creating the connection.</p>
    pub fn client_number(&self) -> &str {
        use std::ops::Deref;
        self.client_number.deref()
    }
    /// <p>The logon language of SAPOData instance.</p>
    pub fn logon_language(&self) -> ::std::option::Option<&str> {
        self.logon_language.as_deref()
    }
    /// <p>The SAPOData Private Link service name to be used for private data transfers.</p>
    pub fn private_link_service_name(&self) -> ::std::option::Option<&str> {
        self.private_link_service_name.as_deref()
    }
    /// <p>The SAPOData OAuth properties required for OAuth type authentication.</p>
    pub fn o_auth_properties(&self) -> ::std::option::Option<&crate::types::OAuthProperties> {
        self.o_auth_properties.as_ref()
    }
    /// <p>If you set this parameter to <code>true</code>, Amazon AppFlow bypasses the single sign-on (SSO) settings in your SAP account when it accesses your SAP OData instance.</p>
    /// <p>Whether you need this option depends on the types of credentials that you applied to your SAP OData connection profile. If your profile uses basic authentication credentials, SAP SSO can prevent Amazon AppFlow from connecting to your account with your username and password. In this case, bypassing SSO makes it possible for Amazon AppFlow to connect successfully. However, if your profile uses OAuth credentials, this parameter has no affect.</p>
    pub fn disable_sso(&self) -> bool {
        self.disable_sso
    }
}
impl SapoDataConnectorProfileProperties {
    /// Creates a new builder-style object to manufacture [`SapoDataConnectorProfileProperties`](crate::types::SapoDataConnectorProfileProperties).
    pub fn builder() -> crate::types::builders::SapoDataConnectorProfilePropertiesBuilder {
        crate::types::builders::SapoDataConnectorProfilePropertiesBuilder::default()
    }
}

/// A builder for [`SapoDataConnectorProfileProperties`](crate::types::SapoDataConnectorProfileProperties).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct SapoDataConnectorProfilePropertiesBuilder {
    pub(crate) application_host_url: ::std::option::Option<::std::string::String>,
    pub(crate) application_service_path: ::std::option::Option<::std::string::String>,
    pub(crate) port_number: ::std::option::Option<i32>,
    pub(crate) client_number: ::std::option::Option<::std::string::String>,
    pub(crate) logon_language: ::std::option::Option<::std::string::String>,
    pub(crate) private_link_service_name: ::std::option::Option<::std::string::String>,
    pub(crate) o_auth_properties: ::std::option::Option<crate::types::OAuthProperties>,
    pub(crate) disable_sso: ::std::option::Option<bool>,
}
impl SapoDataConnectorProfilePropertiesBuilder {
    /// <p>The location of the SAPOData resource.</p>
    /// This field is required.
    pub fn application_host_url(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.application_host_url = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The location of the SAPOData resource.</p>
    pub fn set_application_host_url(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.application_host_url = input;
        self
    }
    /// <p>The location of the SAPOData resource.</p>
    pub fn get_application_host_url(&self) -> &::std::option::Option<::std::string::String> {
        &self.application_host_url
    }
    /// <p>The application path to catalog service.</p>
    /// This field is required.
    pub fn application_service_path(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.application_service_path = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The application path to catalog service.</p>
    pub fn set_application_service_path(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.application_service_path = input;
        self
    }
    /// <p>The application path to catalog service.</p>
    pub fn get_application_service_path(&self) -> &::std::option::Option<::std::string::String> {
        &self.application_service_path
    }
    /// <p>The port number of the SAPOData instance.</p>
    /// This field is required.
    pub fn port_number(mut self, input: i32) -> Self {
        self.port_number = ::std::option::Option::Some(input);
        self
    }
    /// <p>The port number of the SAPOData instance.</p>
    pub fn set_port_number(mut self, input: ::std::option::Option<i32>) -> Self {
        self.port_number = input;
        self
    }
    /// <p>The port number of the SAPOData instance.</p>
    pub fn get_port_number(&self) -> &::std::option::Option<i32> {
        &self.port_number
    }
    /// <p>The client number for the client creating the connection.</p>
    /// This field is required.
    pub fn client_number(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.client_number = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The client number for the client creating the connection.</p>
    pub fn set_client_number(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.client_number = input;
        self
    }
    /// <p>The client number for the client creating the connection.</p>
    pub fn get_client_number(&self) -> &::std::option::Option<::std::string::String> {
        &self.client_number
    }
    /// <p>The logon language of SAPOData instance.</p>
    pub fn logon_language(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.logon_language = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The logon language of SAPOData instance.</p>
    pub fn set_logon_language(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.logon_language = input;
        self
    }
    /// <p>The logon language of SAPOData instance.</p>
    pub fn get_logon_language(&self) -> &::std::option::Option<::std::string::String> {
        &self.logon_language
    }
    /// <p>The SAPOData Private Link service name to be used for private data transfers.</p>
    pub fn private_link_service_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.private_link_service_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The SAPOData Private Link service name to be used for private data transfers.</p>
    pub fn set_private_link_service_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.private_link_service_name = input;
        self
    }
    /// <p>The SAPOData Private Link service name to be used for private data transfers.</p>
    pub fn get_private_link_service_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.private_link_service_name
    }
    /// <p>The SAPOData OAuth properties required for OAuth type authentication.</p>
    pub fn o_auth_properties(mut self, input: crate::types::OAuthProperties) -> Self {
        self.o_auth_properties = ::std::option::Option::Some(input);
        self
    }
    /// <p>The SAPOData OAuth properties required for OAuth type authentication.</p>
    pub fn set_o_auth_properties(mut self, input: ::std::option::Option<crate::types::OAuthProperties>) -> Self {
        self.o_auth_properties = input;
        self
    }
    /// <p>The SAPOData OAuth properties required for OAuth type authentication.</p>
    pub fn get_o_auth_properties(&self) -> &::std::option::Option<crate::types::OAuthProperties> {
        &self.o_auth_properties
    }
    /// <p>If you set this parameter to <code>true</code>, Amazon AppFlow bypasses the single sign-on (SSO) settings in your SAP account when it accesses your SAP OData instance.</p>
    /// <p>Whether you need this option depends on the types of credentials that you applied to your SAP OData connection profile. If your profile uses basic authentication credentials, SAP SSO can prevent Amazon AppFlow from connecting to your account with your username and password. In this case, bypassing SSO makes it possible for Amazon AppFlow to connect successfully. However, if your profile uses OAuth credentials, this parameter has no affect.</p>
    pub fn disable_sso(mut self, input: bool) -> Self {
        self.disable_sso = ::std::option::Option::Some(input);
        self
    }
    /// <p>If you set this parameter to <code>true</code>, Amazon AppFlow bypasses the single sign-on (SSO) settings in your SAP account when it accesses your SAP OData instance.</p>
    /// <p>Whether you need this option depends on the types of credentials that you applied to your SAP OData connection profile. If your profile uses basic authentication credentials, SAP SSO can prevent Amazon AppFlow from connecting to your account with your username and password. In this case, bypassing SSO makes it possible for Amazon AppFlow to connect successfully. However, if your profile uses OAuth credentials, this parameter has no affect.</p>
    pub fn set_disable_sso(mut self, input: ::std::option::Option<bool>) -> Self {
        self.disable_sso = input;
        self
    }
    /// <p>If you set this parameter to <code>true</code>, Amazon AppFlow bypasses the single sign-on (SSO) settings in your SAP account when it accesses your SAP OData instance.</p>
    /// <p>Whether you need this option depends on the types of credentials that you applied to your SAP OData connection profile. If your profile uses basic authentication credentials, SAP SSO can prevent Amazon AppFlow from connecting to your account with your username and password. In this case, bypassing SSO makes it possible for Amazon AppFlow to connect successfully. However, if your profile uses OAuth credentials, this parameter has no affect.</p>
    pub fn get_disable_sso(&self) -> &::std::option::Option<bool> {
        &self.disable_sso
    }
    /// Consumes the builder and constructs a [`SapoDataConnectorProfileProperties`](crate::types::SapoDataConnectorProfileProperties).
    /// This method will fail if any of the following fields are not set:
    /// - [`application_host_url`](crate::types::builders::SapoDataConnectorProfilePropertiesBuilder::application_host_url)
    /// - [`application_service_path`](crate::types::builders::SapoDataConnectorProfilePropertiesBuilder::application_service_path)
    /// - [`port_number`](crate::types::builders::SapoDataConnectorProfilePropertiesBuilder::port_number)
    /// - [`client_number`](crate::types::builders::SapoDataConnectorProfilePropertiesBuilder::client_number)
    pub fn build(self) -> ::std::result::Result<crate::types::SapoDataConnectorProfileProperties, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::SapoDataConnectorProfileProperties {
            application_host_url: self.application_host_url.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "application_host_url",
                    "application_host_url was not specified but it is required when building SapoDataConnectorProfileProperties",
                )
            })?,
            application_service_path: self.application_service_path.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "application_service_path",
                    "application_service_path was not specified but it is required when building SapoDataConnectorProfileProperties",
                )
            })?,
            port_number: self.port_number.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "port_number",
                    "port_number was not specified but it is required when building SapoDataConnectorProfileProperties",
                )
            })?,
            client_number: self.client_number.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "client_number",
                    "client_number was not specified but it is required when building SapoDataConnectorProfileProperties",
                )
            })?,
            logon_language: self.logon_language,
            private_link_service_name: self.private_link_service_name,
            o_auth_properties: self.o_auth_properties,
            disable_sso: self.disable_sso.unwrap_or_default(),
        })
    }
}
