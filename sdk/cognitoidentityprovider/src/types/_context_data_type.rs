// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Contextual user data used for evaluating the risk of an authentication event by user pool threat protection.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ContextDataType {
    /// <p>The source IP address of your user's device.</p>
    pub ip_address: ::std::string::String,
    /// <p>The name of your application's service endpoint.</p>
    pub server_name: ::std::string::String,
    /// <p>The path of your application's service endpoint.</p>
    pub server_path: ::std::string::String,
    /// <p>The HTTP headers from your user's authentication request.</p>
    pub http_headers: ::std::vec::Vec<crate::types::HttpHeader>,
    /// <p>Encoded device-fingerprint details that your app collected with the Amazon Cognito context data collection library. For more information, see <a href="https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-pool-settings-adaptive-authentication.html#user-pool-settings-adaptive-authentication-device-fingerprint">Adding user device and session data to API requests</a>.</p>
    pub encoded_data: ::std::option::Option<::std::string::String>,
}
impl ContextDataType {
    /// <p>The source IP address of your user's device.</p>
    pub fn ip_address(&self) -> &str {
        use std::ops::Deref;
        self.ip_address.deref()
    }
    /// <p>The name of your application's service endpoint.</p>
    pub fn server_name(&self) -> &str {
        use std::ops::Deref;
        self.server_name.deref()
    }
    /// <p>The path of your application's service endpoint.</p>
    pub fn server_path(&self) -> &str {
        use std::ops::Deref;
        self.server_path.deref()
    }
    /// <p>The HTTP headers from your user's authentication request.</p>
    pub fn http_headers(&self) -> &[crate::types::HttpHeader] {
        use std::ops::Deref;
        self.http_headers.deref()
    }
    /// <p>Encoded device-fingerprint details that your app collected with the Amazon Cognito context data collection library. For more information, see <a href="https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-pool-settings-adaptive-authentication.html#user-pool-settings-adaptive-authentication-device-fingerprint">Adding user device and session data to API requests</a>.</p>
    pub fn encoded_data(&self) -> ::std::option::Option<&str> {
        self.encoded_data.as_deref()
    }
}
impl ContextDataType {
    /// Creates a new builder-style object to manufacture [`ContextDataType`](crate::types::ContextDataType).
    pub fn builder() -> crate::types::builders::ContextDataTypeBuilder {
        crate::types::builders::ContextDataTypeBuilder::default()
    }
}

/// A builder for [`ContextDataType`](crate::types::ContextDataType).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ContextDataTypeBuilder {
    pub(crate) ip_address: ::std::option::Option<::std::string::String>,
    pub(crate) server_name: ::std::option::Option<::std::string::String>,
    pub(crate) server_path: ::std::option::Option<::std::string::String>,
    pub(crate) http_headers: ::std::option::Option<::std::vec::Vec<crate::types::HttpHeader>>,
    pub(crate) encoded_data: ::std::option::Option<::std::string::String>,
}
impl ContextDataTypeBuilder {
    /// <p>The source IP address of your user's device.</p>
    /// This field is required.
    pub fn ip_address(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.ip_address = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The source IP address of your user's device.</p>
    pub fn set_ip_address(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.ip_address = input;
        self
    }
    /// <p>The source IP address of your user's device.</p>
    pub fn get_ip_address(&self) -> &::std::option::Option<::std::string::String> {
        &self.ip_address
    }
    /// <p>The name of your application's service endpoint.</p>
    /// This field is required.
    pub fn server_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.server_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of your application's service endpoint.</p>
    pub fn set_server_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.server_name = input;
        self
    }
    /// <p>The name of your application's service endpoint.</p>
    pub fn get_server_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.server_name
    }
    /// <p>The path of your application's service endpoint.</p>
    /// This field is required.
    pub fn server_path(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.server_path = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The path of your application's service endpoint.</p>
    pub fn set_server_path(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.server_path = input;
        self
    }
    /// <p>The path of your application's service endpoint.</p>
    pub fn get_server_path(&self) -> &::std::option::Option<::std::string::String> {
        &self.server_path
    }
    /// Appends an item to `http_headers`.
    ///
    /// To override the contents of this collection use [`set_http_headers`](Self::set_http_headers).
    ///
    /// <p>The HTTP headers from your user's authentication request.</p>
    pub fn http_headers(mut self, input: crate::types::HttpHeader) -> Self {
        let mut v = self.http_headers.unwrap_or_default();
        v.push(input);
        self.http_headers = ::std::option::Option::Some(v);
        self
    }
    /// <p>The HTTP headers from your user's authentication request.</p>
    pub fn set_http_headers(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::HttpHeader>>) -> Self {
        self.http_headers = input;
        self
    }
    /// <p>The HTTP headers from your user's authentication request.</p>
    pub fn get_http_headers(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::HttpHeader>> {
        &self.http_headers
    }
    /// <p>Encoded device-fingerprint details that your app collected with the Amazon Cognito context data collection library. For more information, see <a href="https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-pool-settings-adaptive-authentication.html#user-pool-settings-adaptive-authentication-device-fingerprint">Adding user device and session data to API requests</a>.</p>
    pub fn encoded_data(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.encoded_data = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Encoded device-fingerprint details that your app collected with the Amazon Cognito context data collection library. For more information, see <a href="https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-pool-settings-adaptive-authentication.html#user-pool-settings-adaptive-authentication-device-fingerprint">Adding user device and session data to API requests</a>.</p>
    pub fn set_encoded_data(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.encoded_data = input;
        self
    }
    /// <p>Encoded device-fingerprint details that your app collected with the Amazon Cognito context data collection library. For more information, see <a href="https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-pool-settings-adaptive-authentication.html#user-pool-settings-adaptive-authentication-device-fingerprint">Adding user device and session data to API requests</a>.</p>
    pub fn get_encoded_data(&self) -> &::std::option::Option<::std::string::String> {
        &self.encoded_data
    }
    /// Consumes the builder and constructs a [`ContextDataType`](crate::types::ContextDataType).
    /// This method will fail if any of the following fields are not set:
    /// - [`ip_address`](crate::types::builders::ContextDataTypeBuilder::ip_address)
    /// - [`server_name`](crate::types::builders::ContextDataTypeBuilder::server_name)
    /// - [`server_path`](crate::types::builders::ContextDataTypeBuilder::server_path)
    /// - [`http_headers`](crate::types::builders::ContextDataTypeBuilder::http_headers)
    pub fn build(self) -> ::std::result::Result<crate::types::ContextDataType, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::ContextDataType {
            ip_address: self.ip_address.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "ip_address",
                    "ip_address was not specified but it is required when building ContextDataType",
                )
            })?,
            server_name: self.server_name.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "server_name",
                    "server_name was not specified but it is required when building ContextDataType",
                )
            })?,
            server_path: self.server_path.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "server_path",
                    "server_path was not specified but it is required when building ContextDataType",
                )
            })?,
            http_headers: self.http_headers.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "http_headers",
                    "http_headers was not specified but it is required when building ContextDataType",
                )
            })?,
            encoded_data: self.encoded_data,
        })
    }
}
