// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeProductsV2Output {
    /// <p>Gets information about the product integration.</p>
    pub products_v2: ::std::option::Option<::std::vec::Vec<crate::types::ProductV2>>,
    /// <p>The pagination token to use to request the next page of results. Otherwise, this parameter is null.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl DescribeProductsV2Output {
    /// <p>Gets information about the product integration.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.products_v2.is_none()`.
    pub fn products_v2(&self) -> &[crate::types::ProductV2] {
        self.products_v2.as_deref().unwrap_or_default()
    }
    /// <p>The pagination token to use to request the next page of results. Otherwise, this parameter is null.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for DescribeProductsV2Output {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DescribeProductsV2Output {
    /// Creates a new builder-style object to manufacture [`DescribeProductsV2Output`](crate::operation::describe_products_v2::DescribeProductsV2Output).
    pub fn builder() -> crate::operation::describe_products_v2::builders::DescribeProductsV2OutputBuilder {
        crate::operation::describe_products_v2::builders::DescribeProductsV2OutputBuilder::default()
    }
}

/// A builder for [`DescribeProductsV2Output`](crate::operation::describe_products_v2::DescribeProductsV2Output).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeProductsV2OutputBuilder {
    pub(crate) products_v2: ::std::option::Option<::std::vec::Vec<crate::types::ProductV2>>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl DescribeProductsV2OutputBuilder {
    /// Appends an item to `products_v2`.
    ///
    /// To override the contents of this collection use [`set_products_v2`](Self::set_products_v2).
    ///
    /// <p>Gets information about the product integration.</p>
    pub fn products_v2(mut self, input: crate::types::ProductV2) -> Self {
        let mut v = self.products_v2.unwrap_or_default();
        v.push(input);
        self.products_v2 = ::std::option::Option::Some(v);
        self
    }
    /// <p>Gets information about the product integration.</p>
    pub fn set_products_v2(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::ProductV2>>) -> Self {
        self.products_v2 = input;
        self
    }
    /// <p>Gets information about the product integration.</p>
    pub fn get_products_v2(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::ProductV2>> {
        &self.products_v2
    }
    /// <p>The pagination token to use to request the next page of results. Otherwise, this parameter is null.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The pagination token to use to request the next page of results. Otherwise, this parameter is null.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>The pagination token to use to request the next page of results. Otherwise, this parameter is null.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`DescribeProductsV2Output`](crate::operation::describe_products_v2::DescribeProductsV2Output).
    pub fn build(self) -> crate::operation::describe_products_v2::DescribeProductsV2Output {
        crate::operation::describe_products_v2::DescribeProductsV2Output {
            products_v2: self.products_v2,
            next_token: self.next_token,
            _request_id: self._request_id,
        }
    }
}
