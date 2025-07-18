// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>An object that represents the criteria for determining a request match.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GrpcGatewayRouteMatch {
    /// <p>The fully qualified domain name for the service to match from the request.</p>
    pub service_name: ::std::option::Option<::std::string::String>,
    /// <p>The gateway route host name to be matched on.</p>
    pub hostname: ::std::option::Option<crate::types::GatewayRouteHostnameMatch>,
    /// <p>The gateway route metadata to be matched on.</p>
    pub metadata: ::std::option::Option<::std::vec::Vec<crate::types::GrpcGatewayRouteMetadata>>,
    /// <p>The gateway route port to be matched on.</p>
    pub port: ::std::option::Option<i32>,
}
impl GrpcGatewayRouteMatch {
    /// <p>The fully qualified domain name for the service to match from the request.</p>
    pub fn service_name(&self) -> ::std::option::Option<&str> {
        self.service_name.as_deref()
    }
    /// <p>The gateway route host name to be matched on.</p>
    pub fn hostname(&self) -> ::std::option::Option<&crate::types::GatewayRouteHostnameMatch> {
        self.hostname.as_ref()
    }
    /// <p>The gateway route metadata to be matched on.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.metadata.is_none()`.
    pub fn metadata(&self) -> &[crate::types::GrpcGatewayRouteMetadata] {
        self.metadata.as_deref().unwrap_or_default()
    }
    /// <p>The gateway route port to be matched on.</p>
    pub fn port(&self) -> ::std::option::Option<i32> {
        self.port
    }
}
impl GrpcGatewayRouteMatch {
    /// Creates a new builder-style object to manufacture [`GrpcGatewayRouteMatch`](crate::types::GrpcGatewayRouteMatch).
    pub fn builder() -> crate::types::builders::GrpcGatewayRouteMatchBuilder {
        crate::types::builders::GrpcGatewayRouteMatchBuilder::default()
    }
}

/// A builder for [`GrpcGatewayRouteMatch`](crate::types::GrpcGatewayRouteMatch).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GrpcGatewayRouteMatchBuilder {
    pub(crate) service_name: ::std::option::Option<::std::string::String>,
    pub(crate) hostname: ::std::option::Option<crate::types::GatewayRouteHostnameMatch>,
    pub(crate) metadata: ::std::option::Option<::std::vec::Vec<crate::types::GrpcGatewayRouteMetadata>>,
    pub(crate) port: ::std::option::Option<i32>,
}
impl GrpcGatewayRouteMatchBuilder {
    /// <p>The fully qualified domain name for the service to match from the request.</p>
    pub fn service_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.service_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The fully qualified domain name for the service to match from the request.</p>
    pub fn set_service_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.service_name = input;
        self
    }
    /// <p>The fully qualified domain name for the service to match from the request.</p>
    pub fn get_service_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.service_name
    }
    /// <p>The gateway route host name to be matched on.</p>
    pub fn hostname(mut self, input: crate::types::GatewayRouteHostnameMatch) -> Self {
        self.hostname = ::std::option::Option::Some(input);
        self
    }
    /// <p>The gateway route host name to be matched on.</p>
    pub fn set_hostname(mut self, input: ::std::option::Option<crate::types::GatewayRouteHostnameMatch>) -> Self {
        self.hostname = input;
        self
    }
    /// <p>The gateway route host name to be matched on.</p>
    pub fn get_hostname(&self) -> &::std::option::Option<crate::types::GatewayRouteHostnameMatch> {
        &self.hostname
    }
    /// Appends an item to `metadata`.
    ///
    /// To override the contents of this collection use [`set_metadata`](Self::set_metadata).
    ///
    /// <p>The gateway route metadata to be matched on.</p>
    pub fn metadata(mut self, input: crate::types::GrpcGatewayRouteMetadata) -> Self {
        let mut v = self.metadata.unwrap_or_default();
        v.push(input);
        self.metadata = ::std::option::Option::Some(v);
        self
    }
    /// <p>The gateway route metadata to be matched on.</p>
    pub fn set_metadata(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::GrpcGatewayRouteMetadata>>) -> Self {
        self.metadata = input;
        self
    }
    /// <p>The gateway route metadata to be matched on.</p>
    pub fn get_metadata(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::GrpcGatewayRouteMetadata>> {
        &self.metadata
    }
    /// <p>The gateway route port to be matched on.</p>
    pub fn port(mut self, input: i32) -> Self {
        self.port = ::std::option::Option::Some(input);
        self
    }
    /// <p>The gateway route port to be matched on.</p>
    pub fn set_port(mut self, input: ::std::option::Option<i32>) -> Self {
        self.port = input;
        self
    }
    /// <p>The gateway route port to be matched on.</p>
    pub fn get_port(&self) -> &::std::option::Option<i32> {
        &self.port
    }
    /// Consumes the builder and constructs a [`GrpcGatewayRouteMatch`](crate::types::GrpcGatewayRouteMatch).
    pub fn build(self) -> crate::types::GrpcGatewayRouteMatch {
        crate::types::GrpcGatewayRouteMatch {
            service_name: self.service_name,
            hostname: self.hostname,
            metadata: self.metadata,
            port: self.port,
        }
    }
}
