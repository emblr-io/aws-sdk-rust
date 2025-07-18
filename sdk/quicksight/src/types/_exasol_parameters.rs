// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The required parameters for connecting to an Exasol data source.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ExasolParameters {
    /// <p>The hostname or IP address of the Exasol data source.</p>
    pub host: ::std::string::String,
    /// <p>The port for the Exasol data source.</p>
    pub port: i32,
}
impl ExasolParameters {
    /// <p>The hostname or IP address of the Exasol data source.</p>
    pub fn host(&self) -> &str {
        use std::ops::Deref;
        self.host.deref()
    }
    /// <p>The port for the Exasol data source.</p>
    pub fn port(&self) -> i32 {
        self.port
    }
}
impl ExasolParameters {
    /// Creates a new builder-style object to manufacture [`ExasolParameters`](crate::types::ExasolParameters).
    pub fn builder() -> crate::types::builders::ExasolParametersBuilder {
        crate::types::builders::ExasolParametersBuilder::default()
    }
}

/// A builder for [`ExasolParameters`](crate::types::ExasolParameters).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ExasolParametersBuilder {
    pub(crate) host: ::std::option::Option<::std::string::String>,
    pub(crate) port: ::std::option::Option<i32>,
}
impl ExasolParametersBuilder {
    /// <p>The hostname or IP address of the Exasol data source.</p>
    /// This field is required.
    pub fn host(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.host = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The hostname or IP address of the Exasol data source.</p>
    pub fn set_host(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.host = input;
        self
    }
    /// <p>The hostname or IP address of the Exasol data source.</p>
    pub fn get_host(&self) -> &::std::option::Option<::std::string::String> {
        &self.host
    }
    /// <p>The port for the Exasol data source.</p>
    /// This field is required.
    pub fn port(mut self, input: i32) -> Self {
        self.port = ::std::option::Option::Some(input);
        self
    }
    /// <p>The port for the Exasol data source.</p>
    pub fn set_port(mut self, input: ::std::option::Option<i32>) -> Self {
        self.port = input;
        self
    }
    /// <p>The port for the Exasol data source.</p>
    pub fn get_port(&self) -> &::std::option::Option<i32> {
        &self.port
    }
    /// Consumes the builder and constructs a [`ExasolParameters`](crate::types::ExasolParameters).
    /// This method will fail if any of the following fields are not set:
    /// - [`host`](crate::types::builders::ExasolParametersBuilder::host)
    /// - [`port`](crate::types::builders::ExasolParametersBuilder::port)
    pub fn build(self) -> ::std::result::Result<crate::types::ExasolParameters, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::ExasolParameters {
            host: self.host.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "host",
                    "host was not specified but it is required when building ExasolParameters",
                )
            })?,
            port: self.port.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "port",
                    "port was not specified but it is required when building ExasolParameters",
                )
            })?,
        })
    }
}
