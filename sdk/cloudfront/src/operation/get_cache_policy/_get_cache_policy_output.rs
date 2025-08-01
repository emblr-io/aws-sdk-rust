// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetCachePolicyOutput {
    /// <p>The cache policy.</p>
    pub cache_policy: ::std::option::Option<crate::types::CachePolicy>,
    /// <p>The current version of the cache policy.</p>
    pub e_tag: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl GetCachePolicyOutput {
    /// <p>The cache policy.</p>
    pub fn cache_policy(&self) -> ::std::option::Option<&crate::types::CachePolicy> {
        self.cache_policy.as_ref()
    }
    /// <p>The current version of the cache policy.</p>
    pub fn e_tag(&self) -> ::std::option::Option<&str> {
        self.e_tag.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for GetCachePolicyOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl GetCachePolicyOutput {
    /// Creates a new builder-style object to manufacture [`GetCachePolicyOutput`](crate::operation::get_cache_policy::GetCachePolicyOutput).
    pub fn builder() -> crate::operation::get_cache_policy::builders::GetCachePolicyOutputBuilder {
        crate::operation::get_cache_policy::builders::GetCachePolicyOutputBuilder::default()
    }
}

/// A builder for [`GetCachePolicyOutput`](crate::operation::get_cache_policy::GetCachePolicyOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetCachePolicyOutputBuilder {
    pub(crate) cache_policy: ::std::option::Option<crate::types::CachePolicy>,
    pub(crate) e_tag: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl GetCachePolicyOutputBuilder {
    /// <p>The cache policy.</p>
    pub fn cache_policy(mut self, input: crate::types::CachePolicy) -> Self {
        self.cache_policy = ::std::option::Option::Some(input);
        self
    }
    /// <p>The cache policy.</p>
    pub fn set_cache_policy(mut self, input: ::std::option::Option<crate::types::CachePolicy>) -> Self {
        self.cache_policy = input;
        self
    }
    /// <p>The cache policy.</p>
    pub fn get_cache_policy(&self) -> &::std::option::Option<crate::types::CachePolicy> {
        &self.cache_policy
    }
    /// <p>The current version of the cache policy.</p>
    pub fn e_tag(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.e_tag = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The current version of the cache policy.</p>
    pub fn set_e_tag(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.e_tag = input;
        self
    }
    /// <p>The current version of the cache policy.</p>
    pub fn get_e_tag(&self) -> &::std::option::Option<::std::string::String> {
        &self.e_tag
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`GetCachePolicyOutput`](crate::operation::get_cache_policy::GetCachePolicyOutput).
    pub fn build(self) -> crate::operation::get_cache_policy::GetCachePolicyOutput {
        crate::operation::get_cache_policy::GetCachePolicyOutput {
            cache_policy: self.cache_policy,
            e_tag: self.e_tag,
            _request_id: self._request_id,
        }
    }
}
