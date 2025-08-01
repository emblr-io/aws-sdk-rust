// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Represents the output of a <code>FlushApiCache</code> operation.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct FlushApiCacheOutput {
    _request_id: Option<String>,
}
impl ::aws_types::request_id::RequestId for FlushApiCacheOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl FlushApiCacheOutput {
    /// Creates a new builder-style object to manufacture [`FlushApiCacheOutput`](crate::operation::flush_api_cache::FlushApiCacheOutput).
    pub fn builder() -> crate::operation::flush_api_cache::builders::FlushApiCacheOutputBuilder {
        crate::operation::flush_api_cache::builders::FlushApiCacheOutputBuilder::default()
    }
}

/// A builder for [`FlushApiCacheOutput`](crate::operation::flush_api_cache::FlushApiCacheOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct FlushApiCacheOutputBuilder {
    _request_id: Option<String>,
}
impl FlushApiCacheOutputBuilder {
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`FlushApiCacheOutput`](crate::operation::flush_api_cache::FlushApiCacheOutput).
    pub fn build(self) -> crate::operation::flush_api_cache::FlushApiCacheOutput {
        crate::operation::flush_api_cache::FlushApiCacheOutput {
            _request_id: self._request_id,
        }
    }
}
