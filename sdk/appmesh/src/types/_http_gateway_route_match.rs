// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>An object that represents the criteria for determining a request match.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct HttpGatewayRouteMatch {
    /// <p>Specifies the path to match requests with. This parameter must always start with <code>/</code>, which by itself matches all requests to the virtual service name. You can also match for path-based routing of requests. For example, if your virtual service name is <code>my-service.local</code> and you want the route to match requests to <code>my-service.local/metrics</code>, your prefix should be <code>/metrics</code>.</p>
    pub prefix: ::std::option::Option<::std::string::String>,
    /// <p>The path to match on.</p>
    pub path: ::std::option::Option<crate::types::HttpPathMatch>,
    /// <p>The query parameter to match on.</p>
    pub query_parameters: ::std::option::Option<::std::vec::Vec<crate::types::HttpQueryParameter>>,
    /// <p>The method to match on.</p>
    pub method: ::std::option::Option<crate::types::HttpMethod>,
    /// <p>The host name to match on.</p>
    pub hostname: ::std::option::Option<crate::types::GatewayRouteHostnameMatch>,
    /// <p>The client request headers to match on.</p>
    pub headers: ::std::option::Option<::std::vec::Vec<crate::types::HttpGatewayRouteHeader>>,
    /// <p>The port number to match on.</p>
    pub port: ::std::option::Option<i32>,
}
impl HttpGatewayRouteMatch {
    /// <p>Specifies the path to match requests with. This parameter must always start with <code>/</code>, which by itself matches all requests to the virtual service name. You can also match for path-based routing of requests. For example, if your virtual service name is <code>my-service.local</code> and you want the route to match requests to <code>my-service.local/metrics</code>, your prefix should be <code>/metrics</code>.</p>
    pub fn prefix(&self) -> ::std::option::Option<&str> {
        self.prefix.as_deref()
    }
    /// <p>The path to match on.</p>
    pub fn path(&self) -> ::std::option::Option<&crate::types::HttpPathMatch> {
        self.path.as_ref()
    }
    /// <p>The query parameter to match on.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.query_parameters.is_none()`.
    pub fn query_parameters(&self) -> &[crate::types::HttpQueryParameter] {
        self.query_parameters.as_deref().unwrap_or_default()
    }
    /// <p>The method to match on.</p>
    pub fn method(&self) -> ::std::option::Option<&crate::types::HttpMethod> {
        self.method.as_ref()
    }
    /// <p>The host name to match on.</p>
    pub fn hostname(&self) -> ::std::option::Option<&crate::types::GatewayRouteHostnameMatch> {
        self.hostname.as_ref()
    }
    /// <p>The client request headers to match on.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.headers.is_none()`.
    pub fn headers(&self) -> &[crate::types::HttpGatewayRouteHeader] {
        self.headers.as_deref().unwrap_or_default()
    }
    /// <p>The port number to match on.</p>
    pub fn port(&self) -> ::std::option::Option<i32> {
        self.port
    }
}
impl HttpGatewayRouteMatch {
    /// Creates a new builder-style object to manufacture [`HttpGatewayRouteMatch`](crate::types::HttpGatewayRouteMatch).
    pub fn builder() -> crate::types::builders::HttpGatewayRouteMatchBuilder {
        crate::types::builders::HttpGatewayRouteMatchBuilder::default()
    }
}

/// A builder for [`HttpGatewayRouteMatch`](crate::types::HttpGatewayRouteMatch).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct HttpGatewayRouteMatchBuilder {
    pub(crate) prefix: ::std::option::Option<::std::string::String>,
    pub(crate) path: ::std::option::Option<crate::types::HttpPathMatch>,
    pub(crate) query_parameters: ::std::option::Option<::std::vec::Vec<crate::types::HttpQueryParameter>>,
    pub(crate) method: ::std::option::Option<crate::types::HttpMethod>,
    pub(crate) hostname: ::std::option::Option<crate::types::GatewayRouteHostnameMatch>,
    pub(crate) headers: ::std::option::Option<::std::vec::Vec<crate::types::HttpGatewayRouteHeader>>,
    pub(crate) port: ::std::option::Option<i32>,
}
impl HttpGatewayRouteMatchBuilder {
    /// <p>Specifies the path to match requests with. This parameter must always start with <code>/</code>, which by itself matches all requests to the virtual service name. You can also match for path-based routing of requests. For example, if your virtual service name is <code>my-service.local</code> and you want the route to match requests to <code>my-service.local/metrics</code>, your prefix should be <code>/metrics</code>.</p>
    pub fn prefix(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.prefix = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Specifies the path to match requests with. This parameter must always start with <code>/</code>, which by itself matches all requests to the virtual service name. You can also match for path-based routing of requests. For example, if your virtual service name is <code>my-service.local</code> and you want the route to match requests to <code>my-service.local/metrics</code>, your prefix should be <code>/metrics</code>.</p>
    pub fn set_prefix(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.prefix = input;
        self
    }
    /// <p>Specifies the path to match requests with. This parameter must always start with <code>/</code>, which by itself matches all requests to the virtual service name. You can also match for path-based routing of requests. For example, if your virtual service name is <code>my-service.local</code> and you want the route to match requests to <code>my-service.local/metrics</code>, your prefix should be <code>/metrics</code>.</p>
    pub fn get_prefix(&self) -> &::std::option::Option<::std::string::String> {
        &self.prefix
    }
    /// <p>The path to match on.</p>
    pub fn path(mut self, input: crate::types::HttpPathMatch) -> Self {
        self.path = ::std::option::Option::Some(input);
        self
    }
    /// <p>The path to match on.</p>
    pub fn set_path(mut self, input: ::std::option::Option<crate::types::HttpPathMatch>) -> Self {
        self.path = input;
        self
    }
    /// <p>The path to match on.</p>
    pub fn get_path(&self) -> &::std::option::Option<crate::types::HttpPathMatch> {
        &self.path
    }
    /// Appends an item to `query_parameters`.
    ///
    /// To override the contents of this collection use [`set_query_parameters`](Self::set_query_parameters).
    ///
    /// <p>The query parameter to match on.</p>
    pub fn query_parameters(mut self, input: crate::types::HttpQueryParameter) -> Self {
        let mut v = self.query_parameters.unwrap_or_default();
        v.push(input);
        self.query_parameters = ::std::option::Option::Some(v);
        self
    }
    /// <p>The query parameter to match on.</p>
    pub fn set_query_parameters(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::HttpQueryParameter>>) -> Self {
        self.query_parameters = input;
        self
    }
    /// <p>The query parameter to match on.</p>
    pub fn get_query_parameters(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::HttpQueryParameter>> {
        &self.query_parameters
    }
    /// <p>The method to match on.</p>
    pub fn method(mut self, input: crate::types::HttpMethod) -> Self {
        self.method = ::std::option::Option::Some(input);
        self
    }
    /// <p>The method to match on.</p>
    pub fn set_method(mut self, input: ::std::option::Option<crate::types::HttpMethod>) -> Self {
        self.method = input;
        self
    }
    /// <p>The method to match on.</p>
    pub fn get_method(&self) -> &::std::option::Option<crate::types::HttpMethod> {
        &self.method
    }
    /// <p>The host name to match on.</p>
    pub fn hostname(mut self, input: crate::types::GatewayRouteHostnameMatch) -> Self {
        self.hostname = ::std::option::Option::Some(input);
        self
    }
    /// <p>The host name to match on.</p>
    pub fn set_hostname(mut self, input: ::std::option::Option<crate::types::GatewayRouteHostnameMatch>) -> Self {
        self.hostname = input;
        self
    }
    /// <p>The host name to match on.</p>
    pub fn get_hostname(&self) -> &::std::option::Option<crate::types::GatewayRouteHostnameMatch> {
        &self.hostname
    }
    /// Appends an item to `headers`.
    ///
    /// To override the contents of this collection use [`set_headers`](Self::set_headers).
    ///
    /// <p>The client request headers to match on.</p>
    pub fn headers(mut self, input: crate::types::HttpGatewayRouteHeader) -> Self {
        let mut v = self.headers.unwrap_or_default();
        v.push(input);
        self.headers = ::std::option::Option::Some(v);
        self
    }
    /// <p>The client request headers to match on.</p>
    pub fn set_headers(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::HttpGatewayRouteHeader>>) -> Self {
        self.headers = input;
        self
    }
    /// <p>The client request headers to match on.</p>
    pub fn get_headers(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::HttpGatewayRouteHeader>> {
        &self.headers
    }
    /// <p>The port number to match on.</p>
    pub fn port(mut self, input: i32) -> Self {
        self.port = ::std::option::Option::Some(input);
        self
    }
    /// <p>The port number to match on.</p>
    pub fn set_port(mut self, input: ::std::option::Option<i32>) -> Self {
        self.port = input;
        self
    }
    /// <p>The port number to match on.</p>
    pub fn get_port(&self) -> &::std::option::Option<i32> {
        &self.port
    }
    /// Consumes the builder and constructs a [`HttpGatewayRouteMatch`](crate::types::HttpGatewayRouteMatch).
    pub fn build(self) -> crate::types::HttpGatewayRouteMatch {
        crate::types::HttpGatewayRouteMatch {
            prefix: self.prefix,
            path: self.path,
            query_parameters: self.query_parameters,
            method: self.method,
            hostname: self.hostname,
            headers: self.headers,
            port: self.port,
        }
    }
}
