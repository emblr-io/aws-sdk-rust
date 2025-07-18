// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Specifies the request's HTTP method as an aggregate key for a rate-based rule. Each distinct HTTP method contributes to the aggregation instance. If you use just the HTTP method as your custom key, then each method fully defines an aggregation instance.</p>
/// <p>JSON specification: <code>"RateLimitHTTPMethod": {}</code></p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct RateLimitHttpMethod {}
impl RateLimitHttpMethod {
    /// Creates a new builder-style object to manufacture [`RateLimitHttpMethod`](crate::types::RateLimitHttpMethod).
    pub fn builder() -> crate::types::builders::RateLimitHttpMethodBuilder {
        crate::types::builders::RateLimitHttpMethodBuilder::default()
    }
}

/// A builder for [`RateLimitHttpMethod`](crate::types::RateLimitHttpMethod).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct RateLimitHttpMethodBuilder {}
impl RateLimitHttpMethodBuilder {
    /// Consumes the builder and constructs a [`RateLimitHttpMethod`](crate::types::RateLimitHttpMethod).
    pub fn build(self) -> crate::types::RateLimitHttpMethod {
        crate::types::RateLimitHttpMethod {}
    }
}
