// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The parameters for OpenSearch.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AmazonElasticsearchParameters {
    /// <p>The OpenSearch domain.</p>
    pub domain: ::std::string::String,
}
impl AmazonElasticsearchParameters {
    /// <p>The OpenSearch domain.</p>
    pub fn domain(&self) -> &str {
        use std::ops::Deref;
        self.domain.deref()
    }
}
impl AmazonElasticsearchParameters {
    /// Creates a new builder-style object to manufacture [`AmazonElasticsearchParameters`](crate::types::AmazonElasticsearchParameters).
    pub fn builder() -> crate::types::builders::AmazonElasticsearchParametersBuilder {
        crate::types::builders::AmazonElasticsearchParametersBuilder::default()
    }
}

/// A builder for [`AmazonElasticsearchParameters`](crate::types::AmazonElasticsearchParameters).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AmazonElasticsearchParametersBuilder {
    pub(crate) domain: ::std::option::Option<::std::string::String>,
}
impl AmazonElasticsearchParametersBuilder {
    /// <p>The OpenSearch domain.</p>
    /// This field is required.
    pub fn domain(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.domain = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The OpenSearch domain.</p>
    pub fn set_domain(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.domain = input;
        self
    }
    /// <p>The OpenSearch domain.</p>
    pub fn get_domain(&self) -> &::std::option::Option<::std::string::String> {
        &self.domain
    }
    /// Consumes the builder and constructs a [`AmazonElasticsearchParameters`](crate::types::AmazonElasticsearchParameters).
    /// This method will fail if any of the following fields are not set:
    /// - [`domain`](crate::types::builders::AmazonElasticsearchParametersBuilder::domain)
    pub fn build(self) -> ::std::result::Result<crate::types::AmazonElasticsearchParameters, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::AmazonElasticsearchParameters {
            domain: self.domain.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "domain",
                    "domain was not specified but it is required when building AmazonElasticsearchParameters",
                )
            })?,
        })
    }
}
