// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The physical endpoints of a connection.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct PhysicalEndpoint {
    /// <p>The location of a connection.</p>
    pub aws_location: ::std::option::Option<crate::types::AwsLocation>,
    /// <p>The Amazon Web Services Glue connection name.</p>
    pub glue_connection_name: ::std::option::Option<::std::string::String>,
    /// <p>The Amazon Web Services Glue connection.</p>
    pub glue_connection: ::std::option::Option<crate::types::GlueConnection>,
    /// <p>The host in the physical endpoints of a connection.</p>
    pub host: ::std::option::Option<::std::string::String>,
    /// <p>The port in the physical endpoints of a connection.</p>
    pub port: ::std::option::Option<i32>,
    /// <p>The protocol in the physical endpoints of a connection.</p>
    pub protocol: ::std::option::Option<crate::types::Protocol>,
    /// <p>The stage in the physical endpoints of a connection.</p>
    pub stage: ::std::option::Option<::std::string::String>,
}
impl PhysicalEndpoint {
    /// <p>The location of a connection.</p>
    pub fn aws_location(&self) -> ::std::option::Option<&crate::types::AwsLocation> {
        self.aws_location.as_ref()
    }
    /// <p>The Amazon Web Services Glue connection name.</p>
    pub fn glue_connection_name(&self) -> ::std::option::Option<&str> {
        self.glue_connection_name.as_deref()
    }
    /// <p>The Amazon Web Services Glue connection.</p>
    pub fn glue_connection(&self) -> ::std::option::Option<&crate::types::GlueConnection> {
        self.glue_connection.as_ref()
    }
    /// <p>The host in the physical endpoints of a connection.</p>
    pub fn host(&self) -> ::std::option::Option<&str> {
        self.host.as_deref()
    }
    /// <p>The port in the physical endpoints of a connection.</p>
    pub fn port(&self) -> ::std::option::Option<i32> {
        self.port
    }
    /// <p>The protocol in the physical endpoints of a connection.</p>
    pub fn protocol(&self) -> ::std::option::Option<&crate::types::Protocol> {
        self.protocol.as_ref()
    }
    /// <p>The stage in the physical endpoints of a connection.</p>
    pub fn stage(&self) -> ::std::option::Option<&str> {
        self.stage.as_deref()
    }
}
impl PhysicalEndpoint {
    /// Creates a new builder-style object to manufacture [`PhysicalEndpoint`](crate::types::PhysicalEndpoint).
    pub fn builder() -> crate::types::builders::PhysicalEndpointBuilder {
        crate::types::builders::PhysicalEndpointBuilder::default()
    }
}

/// A builder for [`PhysicalEndpoint`](crate::types::PhysicalEndpoint).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct PhysicalEndpointBuilder {
    pub(crate) aws_location: ::std::option::Option<crate::types::AwsLocation>,
    pub(crate) glue_connection_name: ::std::option::Option<::std::string::String>,
    pub(crate) glue_connection: ::std::option::Option<crate::types::GlueConnection>,
    pub(crate) host: ::std::option::Option<::std::string::String>,
    pub(crate) port: ::std::option::Option<i32>,
    pub(crate) protocol: ::std::option::Option<crate::types::Protocol>,
    pub(crate) stage: ::std::option::Option<::std::string::String>,
}
impl PhysicalEndpointBuilder {
    /// <p>The location of a connection.</p>
    pub fn aws_location(mut self, input: crate::types::AwsLocation) -> Self {
        self.aws_location = ::std::option::Option::Some(input);
        self
    }
    /// <p>The location of a connection.</p>
    pub fn set_aws_location(mut self, input: ::std::option::Option<crate::types::AwsLocation>) -> Self {
        self.aws_location = input;
        self
    }
    /// <p>The location of a connection.</p>
    pub fn get_aws_location(&self) -> &::std::option::Option<crate::types::AwsLocation> {
        &self.aws_location
    }
    /// <p>The Amazon Web Services Glue connection name.</p>
    pub fn glue_connection_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.glue_connection_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Web Services Glue connection name.</p>
    pub fn set_glue_connection_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.glue_connection_name = input;
        self
    }
    /// <p>The Amazon Web Services Glue connection name.</p>
    pub fn get_glue_connection_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.glue_connection_name
    }
    /// <p>The Amazon Web Services Glue connection.</p>
    pub fn glue_connection(mut self, input: crate::types::GlueConnection) -> Self {
        self.glue_connection = ::std::option::Option::Some(input);
        self
    }
    /// <p>The Amazon Web Services Glue connection.</p>
    pub fn set_glue_connection(mut self, input: ::std::option::Option<crate::types::GlueConnection>) -> Self {
        self.glue_connection = input;
        self
    }
    /// <p>The Amazon Web Services Glue connection.</p>
    pub fn get_glue_connection(&self) -> &::std::option::Option<crate::types::GlueConnection> {
        &self.glue_connection
    }
    /// <p>The host in the physical endpoints of a connection.</p>
    pub fn host(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.host = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The host in the physical endpoints of a connection.</p>
    pub fn set_host(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.host = input;
        self
    }
    /// <p>The host in the physical endpoints of a connection.</p>
    pub fn get_host(&self) -> &::std::option::Option<::std::string::String> {
        &self.host
    }
    /// <p>The port in the physical endpoints of a connection.</p>
    pub fn port(mut self, input: i32) -> Self {
        self.port = ::std::option::Option::Some(input);
        self
    }
    /// <p>The port in the physical endpoints of a connection.</p>
    pub fn set_port(mut self, input: ::std::option::Option<i32>) -> Self {
        self.port = input;
        self
    }
    /// <p>The port in the physical endpoints of a connection.</p>
    pub fn get_port(&self) -> &::std::option::Option<i32> {
        &self.port
    }
    /// <p>The protocol in the physical endpoints of a connection.</p>
    pub fn protocol(mut self, input: crate::types::Protocol) -> Self {
        self.protocol = ::std::option::Option::Some(input);
        self
    }
    /// <p>The protocol in the physical endpoints of a connection.</p>
    pub fn set_protocol(mut self, input: ::std::option::Option<crate::types::Protocol>) -> Self {
        self.protocol = input;
        self
    }
    /// <p>The protocol in the physical endpoints of a connection.</p>
    pub fn get_protocol(&self) -> &::std::option::Option<crate::types::Protocol> {
        &self.protocol
    }
    /// <p>The stage in the physical endpoints of a connection.</p>
    pub fn stage(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.stage = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The stage in the physical endpoints of a connection.</p>
    pub fn set_stage(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.stage = input;
        self
    }
    /// <p>The stage in the physical endpoints of a connection.</p>
    pub fn get_stage(&self) -> &::std::option::Option<::std::string::String> {
        &self.stage
    }
    /// Consumes the builder and constructs a [`PhysicalEndpoint`](crate::types::PhysicalEndpoint).
    pub fn build(self) -> crate::types::PhysicalEndpoint {
        crate::types::PhysicalEndpoint {
            aws_location: self.aws_location,
            glue_connection_name: self.glue_connection_name,
            glue_connection: self.glue_connection,
            host: self.host,
            port: self.port,
            protocol: self.protocol,
            stage: self.stage,
        }
    }
}
