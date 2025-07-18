// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetResolverQueryLogConfigOutput {
    /// <p>Information about the Resolver query logging configuration that you specified in a <code>GetQueryLogConfig</code> request.</p>
    pub resolver_query_log_config: ::std::option::Option<crate::types::ResolverQueryLogConfig>,
    _request_id: Option<String>,
}
impl GetResolverQueryLogConfigOutput {
    /// <p>Information about the Resolver query logging configuration that you specified in a <code>GetQueryLogConfig</code> request.</p>
    pub fn resolver_query_log_config(&self) -> ::std::option::Option<&crate::types::ResolverQueryLogConfig> {
        self.resolver_query_log_config.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for GetResolverQueryLogConfigOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl GetResolverQueryLogConfigOutput {
    /// Creates a new builder-style object to manufacture [`GetResolverQueryLogConfigOutput`](crate::operation::get_resolver_query_log_config::GetResolverQueryLogConfigOutput).
    pub fn builder() -> crate::operation::get_resolver_query_log_config::builders::GetResolverQueryLogConfigOutputBuilder {
        crate::operation::get_resolver_query_log_config::builders::GetResolverQueryLogConfigOutputBuilder::default()
    }
}

/// A builder for [`GetResolverQueryLogConfigOutput`](crate::operation::get_resolver_query_log_config::GetResolverQueryLogConfigOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetResolverQueryLogConfigOutputBuilder {
    pub(crate) resolver_query_log_config: ::std::option::Option<crate::types::ResolverQueryLogConfig>,
    _request_id: Option<String>,
}
impl GetResolverQueryLogConfigOutputBuilder {
    /// <p>Information about the Resolver query logging configuration that you specified in a <code>GetQueryLogConfig</code> request.</p>
    pub fn resolver_query_log_config(mut self, input: crate::types::ResolverQueryLogConfig) -> Self {
        self.resolver_query_log_config = ::std::option::Option::Some(input);
        self
    }
    /// <p>Information about the Resolver query logging configuration that you specified in a <code>GetQueryLogConfig</code> request.</p>
    pub fn set_resolver_query_log_config(mut self, input: ::std::option::Option<crate::types::ResolverQueryLogConfig>) -> Self {
        self.resolver_query_log_config = input;
        self
    }
    /// <p>Information about the Resolver query logging configuration that you specified in a <code>GetQueryLogConfig</code> request.</p>
    pub fn get_resolver_query_log_config(&self) -> &::std::option::Option<crate::types::ResolverQueryLogConfig> {
        &self.resolver_query_log_config
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`GetResolverQueryLogConfigOutput`](crate::operation::get_resolver_query_log_config::GetResolverQueryLogConfigOutput).
    pub fn build(self) -> crate::operation::get_resolver_query_log_config::GetResolverQueryLogConfigOutput {
        crate::operation::get_resolver_query_log_config::GetResolverQueryLogConfigOutput {
            resolver_query_log_config: self.resolver_query_log_config,
            _request_id: self._request_id,
        }
    }
}
