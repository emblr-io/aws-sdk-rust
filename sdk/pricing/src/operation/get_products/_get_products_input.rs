// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetProductsInput {
    /// <p>The code for the service whose products you want to retrieve.</p>
    pub service_code: ::std::option::Option<::std::string::String>,
    /// <p>The list of filters that limit the returned products. only products that match all filters are returned.</p>
    pub filters: ::std::option::Option<::std::vec::Vec<crate::types::Filter>>,
    /// <p>The format version that you want the response to be in.</p>
    /// <p>Valid values are: <code>aws_v1</code></p>
    pub format_version: ::std::option::Option<::std::string::String>,
    /// <p>The pagination token that indicates the next set of results that you want to retrieve.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    /// <p>The maximum number of results to return in the response.</p>
    pub max_results: ::std::option::Option<i32>,
}
impl GetProductsInput {
    /// <p>The code for the service whose products you want to retrieve.</p>
    pub fn service_code(&self) -> ::std::option::Option<&str> {
        self.service_code.as_deref()
    }
    /// <p>The list of filters that limit the returned products. only products that match all filters are returned.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.filters.is_none()`.
    pub fn filters(&self) -> &[crate::types::Filter] {
        self.filters.as_deref().unwrap_or_default()
    }
    /// <p>The format version that you want the response to be in.</p>
    /// <p>Valid values are: <code>aws_v1</code></p>
    pub fn format_version(&self) -> ::std::option::Option<&str> {
        self.format_version.as_deref()
    }
    /// <p>The pagination token that indicates the next set of results that you want to retrieve.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
    /// <p>The maximum number of results to return in the response.</p>
    pub fn max_results(&self) -> ::std::option::Option<i32> {
        self.max_results
    }
}
impl GetProductsInput {
    /// Creates a new builder-style object to manufacture [`GetProductsInput`](crate::operation::get_products::GetProductsInput).
    pub fn builder() -> crate::operation::get_products::builders::GetProductsInputBuilder {
        crate::operation::get_products::builders::GetProductsInputBuilder::default()
    }
}

/// A builder for [`GetProductsInput`](crate::operation::get_products::GetProductsInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetProductsInputBuilder {
    pub(crate) service_code: ::std::option::Option<::std::string::String>,
    pub(crate) filters: ::std::option::Option<::std::vec::Vec<crate::types::Filter>>,
    pub(crate) format_version: ::std::option::Option<::std::string::String>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    pub(crate) max_results: ::std::option::Option<i32>,
}
impl GetProductsInputBuilder {
    /// <p>The code for the service whose products you want to retrieve.</p>
    /// This field is required.
    pub fn service_code(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.service_code = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The code for the service whose products you want to retrieve.</p>
    pub fn set_service_code(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.service_code = input;
        self
    }
    /// <p>The code for the service whose products you want to retrieve.</p>
    pub fn get_service_code(&self) -> &::std::option::Option<::std::string::String> {
        &self.service_code
    }
    /// Appends an item to `filters`.
    ///
    /// To override the contents of this collection use [`set_filters`](Self::set_filters).
    ///
    /// <p>The list of filters that limit the returned products. only products that match all filters are returned.</p>
    pub fn filters(mut self, input: crate::types::Filter) -> Self {
        let mut v = self.filters.unwrap_or_default();
        v.push(input);
        self.filters = ::std::option::Option::Some(v);
        self
    }
    /// <p>The list of filters that limit the returned products. only products that match all filters are returned.</p>
    pub fn set_filters(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Filter>>) -> Self {
        self.filters = input;
        self
    }
    /// <p>The list of filters that limit the returned products. only products that match all filters are returned.</p>
    pub fn get_filters(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Filter>> {
        &self.filters
    }
    /// <p>The format version that you want the response to be in.</p>
    /// <p>Valid values are: <code>aws_v1</code></p>
    pub fn format_version(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.format_version = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The format version that you want the response to be in.</p>
    /// <p>Valid values are: <code>aws_v1</code></p>
    pub fn set_format_version(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.format_version = input;
        self
    }
    /// <p>The format version that you want the response to be in.</p>
    /// <p>Valid values are: <code>aws_v1</code></p>
    pub fn get_format_version(&self) -> &::std::option::Option<::std::string::String> {
        &self.format_version
    }
    /// <p>The pagination token that indicates the next set of results that you want to retrieve.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The pagination token that indicates the next set of results that you want to retrieve.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>The pagination token that indicates the next set of results that you want to retrieve.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// <p>The maximum number of results to return in the response.</p>
    pub fn max_results(mut self, input: i32) -> Self {
        self.max_results = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum number of results to return in the response.</p>
    pub fn set_max_results(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_results = input;
        self
    }
    /// <p>The maximum number of results to return in the response.</p>
    pub fn get_max_results(&self) -> &::std::option::Option<i32> {
        &self.max_results
    }
    /// Consumes the builder and constructs a [`GetProductsInput`](crate::operation::get_products::GetProductsInput).
    pub fn build(self) -> ::std::result::Result<crate::operation::get_products::GetProductsInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::get_products::GetProductsInput {
            service_code: self.service_code,
            filters: self.filters,
            format_version: self.format_version,
            next_token: self.next_token,
            max_results: self.max_results,
        })
    }
}
