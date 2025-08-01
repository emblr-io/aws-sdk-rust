// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Describes the status of the Client VPN endpoint attribute.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AwsEc2ClientVpnEndpointClientConnectOptionsStatusDetails {
    /// <p>The status code.</p>
    pub code: ::std::option::Option<::std::string::String>,
    /// <p>The status message.</p>
    pub message: ::std::option::Option<::std::string::String>,
}
impl AwsEc2ClientVpnEndpointClientConnectOptionsStatusDetails {
    /// <p>The status code.</p>
    pub fn code(&self) -> ::std::option::Option<&str> {
        self.code.as_deref()
    }
    /// <p>The status message.</p>
    pub fn message(&self) -> ::std::option::Option<&str> {
        self.message.as_deref()
    }
}
impl AwsEc2ClientVpnEndpointClientConnectOptionsStatusDetails {
    /// Creates a new builder-style object to manufacture [`AwsEc2ClientVpnEndpointClientConnectOptionsStatusDetails`](crate::types::AwsEc2ClientVpnEndpointClientConnectOptionsStatusDetails).
    pub fn builder() -> crate::types::builders::AwsEc2ClientVpnEndpointClientConnectOptionsStatusDetailsBuilder {
        crate::types::builders::AwsEc2ClientVpnEndpointClientConnectOptionsStatusDetailsBuilder::default()
    }
}

/// A builder for [`AwsEc2ClientVpnEndpointClientConnectOptionsStatusDetails`](crate::types::AwsEc2ClientVpnEndpointClientConnectOptionsStatusDetails).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AwsEc2ClientVpnEndpointClientConnectOptionsStatusDetailsBuilder {
    pub(crate) code: ::std::option::Option<::std::string::String>,
    pub(crate) message: ::std::option::Option<::std::string::String>,
}
impl AwsEc2ClientVpnEndpointClientConnectOptionsStatusDetailsBuilder {
    /// <p>The status code.</p>
    pub fn code(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.code = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The status code.</p>
    pub fn set_code(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.code = input;
        self
    }
    /// <p>The status code.</p>
    pub fn get_code(&self) -> &::std::option::Option<::std::string::String> {
        &self.code
    }
    /// <p>The status message.</p>
    pub fn message(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.message = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The status message.</p>
    pub fn set_message(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.message = input;
        self
    }
    /// <p>The status message.</p>
    pub fn get_message(&self) -> &::std::option::Option<::std::string::String> {
        &self.message
    }
    /// Consumes the builder and constructs a [`AwsEc2ClientVpnEndpointClientConnectOptionsStatusDetails`](crate::types::AwsEc2ClientVpnEndpointClientConnectOptionsStatusDetails).
    pub fn build(self) -> crate::types::AwsEc2ClientVpnEndpointClientConnectOptionsStatusDetails {
        crate::types::AwsEc2ClientVpnEndpointClientConnectOptionsStatusDetails {
            code: self.code,
            message: self.message,
        }
    }
}
