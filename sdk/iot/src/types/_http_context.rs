// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Specifies the HTTP context to use for the test authorizer request.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct HttpContext {
    /// <p>The header keys and values in an HTTP authorization request.</p>
    pub headers: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    /// <p>The query string keys and values in an HTTP authorization request.</p>
    pub query_string: ::std::option::Option<::std::string::String>,
}
impl HttpContext {
    /// <p>The header keys and values in an HTTP authorization request.</p>
    pub fn headers(&self) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        self.headers.as_ref()
    }
    /// <p>The query string keys and values in an HTTP authorization request.</p>
    pub fn query_string(&self) -> ::std::option::Option<&str> {
        self.query_string.as_deref()
    }
}
impl HttpContext {
    /// Creates a new builder-style object to manufacture [`HttpContext`](crate::types::HttpContext).
    pub fn builder() -> crate::types::builders::HttpContextBuilder {
        crate::types::builders::HttpContextBuilder::default()
    }
}

/// A builder for [`HttpContext`](crate::types::HttpContext).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct HttpContextBuilder {
    pub(crate) headers: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    pub(crate) query_string: ::std::option::Option<::std::string::String>,
}
impl HttpContextBuilder {
    /// Adds a key-value pair to `headers`.
    ///
    /// To override the contents of this collection use [`set_headers`](Self::set_headers).
    ///
    /// <p>The header keys and values in an HTTP authorization request.</p>
    pub fn headers(mut self, k: impl ::std::convert::Into<::std::string::String>, v: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut hash_map = self.headers.unwrap_or_default();
        hash_map.insert(k.into(), v.into());
        self.headers = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>The header keys and values in an HTTP authorization request.</p>
    pub fn set_headers(mut self, input: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>) -> Self {
        self.headers = input;
        self
    }
    /// <p>The header keys and values in an HTTP authorization request.</p>
    pub fn get_headers(&self) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        &self.headers
    }
    /// <p>The query string keys and values in an HTTP authorization request.</p>
    pub fn query_string(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.query_string = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The query string keys and values in an HTTP authorization request.</p>
    pub fn set_query_string(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.query_string = input;
        self
    }
    /// <p>The query string keys and values in an HTTP authorization request.</p>
    pub fn get_query_string(&self) -> &::std::option::Option<::std::string::String> {
        &self.query_string
    }
    /// Consumes the builder and constructs a [`HttpContext`](crate::types::HttpContext).
    pub fn build(self) -> crate::types::HttpContext {
        crate::types::HttpContext {
            headers: self.headers,
            query_string: self.query_string,
        }
    }
}
