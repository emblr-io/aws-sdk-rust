// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListSourceViewsForBillingViewOutput {
    /// <p>A list of billing views used as the data source for the custom billing view.</p>
    pub source_views: ::std::vec::Vec<::std::string::String>,
    /// <p>The pagination token that is used on subsequent calls to list billing views.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListSourceViewsForBillingViewOutput {
    /// <p>A list of billing views used as the data source for the custom billing view.</p>
    pub fn source_views(&self) -> &[::std::string::String] {
        use std::ops::Deref;
        self.source_views.deref()
    }
    /// <p>The pagination token that is used on subsequent calls to list billing views.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for ListSourceViewsForBillingViewOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl ListSourceViewsForBillingViewOutput {
    /// Creates a new builder-style object to manufacture [`ListSourceViewsForBillingViewOutput`](crate::operation::list_source_views_for_billing_view::ListSourceViewsForBillingViewOutput).
    pub fn builder() -> crate::operation::list_source_views_for_billing_view::builders::ListSourceViewsForBillingViewOutputBuilder {
        crate::operation::list_source_views_for_billing_view::builders::ListSourceViewsForBillingViewOutputBuilder::default()
    }
}

/// A builder for [`ListSourceViewsForBillingViewOutput`](crate::operation::list_source_views_for_billing_view::ListSourceViewsForBillingViewOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListSourceViewsForBillingViewOutputBuilder {
    pub(crate) source_views: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListSourceViewsForBillingViewOutputBuilder {
    /// Appends an item to `source_views`.
    ///
    /// To override the contents of this collection use [`set_source_views`](Self::set_source_views).
    ///
    /// <p>A list of billing views used as the data source for the custom billing view.</p>
    pub fn source_views(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.source_views.unwrap_or_default();
        v.push(input.into());
        self.source_views = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of billing views used as the data source for the custom billing view.</p>
    pub fn set_source_views(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.source_views = input;
        self
    }
    /// <p>A list of billing views used as the data source for the custom billing view.</p>
    pub fn get_source_views(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.source_views
    }
    /// <p>The pagination token that is used on subsequent calls to list billing views.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The pagination token that is used on subsequent calls to list billing views.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>The pagination token that is used on subsequent calls to list billing views.</p>
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
    /// Consumes the builder and constructs a [`ListSourceViewsForBillingViewOutput`](crate::operation::list_source_views_for_billing_view::ListSourceViewsForBillingViewOutput).
    /// This method will fail if any of the following fields are not set:
    /// - [`source_views`](crate::operation::list_source_views_for_billing_view::builders::ListSourceViewsForBillingViewOutputBuilder::source_views)
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::list_source_views_for_billing_view::ListSourceViewsForBillingViewOutput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(
            crate::operation::list_source_views_for_billing_view::ListSourceViewsForBillingViewOutput {
                source_views: self.source_views.ok_or_else(|| {
                    ::aws_smithy_types::error::operation::BuildError::missing_field(
                        "source_views",
                        "source_views was not specified but it is required when building ListSourceViewsForBillingViewOutput",
                    )
                })?,
                next_token: self.next_token,
                _request_id: self._request_id,
            },
        )
    }
}
