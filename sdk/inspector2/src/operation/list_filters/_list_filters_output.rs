// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListFiltersOutput {
    /// <p>Contains details on the filters associated with your account.</p>
    pub filters: ::std::vec::Vec<crate::types::Filter>,
    /// <p>A token to use for paginating results that are returned in the response. Set the value of this parameter to null for the first request to a list action. For subsequent calls, use the <code>NextToken</code> value returned from the previous request to continue listing results after the first page.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListFiltersOutput {
    /// <p>Contains details on the filters associated with your account.</p>
    pub fn filters(&self) -> &[crate::types::Filter] {
        use std::ops::Deref;
        self.filters.deref()
    }
    /// <p>A token to use for paginating results that are returned in the response. Set the value of this parameter to null for the first request to a list action. For subsequent calls, use the <code>NextToken</code> value returned from the previous request to continue listing results after the first page.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for ListFiltersOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl ListFiltersOutput {
    /// Creates a new builder-style object to manufacture [`ListFiltersOutput`](crate::operation::list_filters::ListFiltersOutput).
    pub fn builder() -> crate::operation::list_filters::builders::ListFiltersOutputBuilder {
        crate::operation::list_filters::builders::ListFiltersOutputBuilder::default()
    }
}

/// A builder for [`ListFiltersOutput`](crate::operation::list_filters::ListFiltersOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListFiltersOutputBuilder {
    pub(crate) filters: ::std::option::Option<::std::vec::Vec<crate::types::Filter>>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListFiltersOutputBuilder {
    /// Appends an item to `filters`.
    ///
    /// To override the contents of this collection use [`set_filters`](Self::set_filters).
    ///
    /// <p>Contains details on the filters associated with your account.</p>
    pub fn filters(mut self, input: crate::types::Filter) -> Self {
        let mut v = self.filters.unwrap_or_default();
        v.push(input);
        self.filters = ::std::option::Option::Some(v);
        self
    }
    /// <p>Contains details on the filters associated with your account.</p>
    pub fn set_filters(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Filter>>) -> Self {
        self.filters = input;
        self
    }
    /// <p>Contains details on the filters associated with your account.</p>
    pub fn get_filters(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Filter>> {
        &self.filters
    }
    /// <p>A token to use for paginating results that are returned in the response. Set the value of this parameter to null for the first request to a list action. For subsequent calls, use the <code>NextToken</code> value returned from the previous request to continue listing results after the first page.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A token to use for paginating results that are returned in the response. Set the value of this parameter to null for the first request to a list action. For subsequent calls, use the <code>NextToken</code> value returned from the previous request to continue listing results after the first page.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>A token to use for paginating results that are returned in the response. Set the value of this parameter to null for the first request to a list action. For subsequent calls, use the <code>NextToken</code> value returned from the previous request to continue listing results after the first page.</p>
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
    /// Consumes the builder and constructs a [`ListFiltersOutput`](crate::operation::list_filters::ListFiltersOutput).
    /// This method will fail if any of the following fields are not set:
    /// - [`filters`](crate::operation::list_filters::builders::ListFiltersOutputBuilder::filters)
    pub fn build(self) -> ::std::result::Result<crate::operation::list_filters::ListFiltersOutput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::list_filters::ListFiltersOutput {
            filters: self.filters.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "filters",
                    "filters was not specified but it is required when building ListFiltersOutput",
                )
            })?,
            next_token: self.next_token,
            _request_id: self._request_id,
        })
    }
}
