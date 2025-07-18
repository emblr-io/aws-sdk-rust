// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Output of a list lenses call.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListLensesOutput {
    /// <p>List of lens summaries of available lenses.</p>
    pub lens_summaries: ::std::option::Option<::std::vec::Vec<crate::types::LensSummary>>,
    /// <p>The token to use to retrieve the next set of results.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListLensesOutput {
    /// <p>List of lens summaries of available lenses.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.lens_summaries.is_none()`.
    pub fn lens_summaries(&self) -> &[crate::types::LensSummary] {
        self.lens_summaries.as_deref().unwrap_or_default()
    }
    /// <p>The token to use to retrieve the next set of results.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for ListLensesOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl ListLensesOutput {
    /// Creates a new builder-style object to manufacture [`ListLensesOutput`](crate::operation::list_lenses::ListLensesOutput).
    pub fn builder() -> crate::operation::list_lenses::builders::ListLensesOutputBuilder {
        crate::operation::list_lenses::builders::ListLensesOutputBuilder::default()
    }
}

/// A builder for [`ListLensesOutput`](crate::operation::list_lenses::ListLensesOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListLensesOutputBuilder {
    pub(crate) lens_summaries: ::std::option::Option<::std::vec::Vec<crate::types::LensSummary>>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListLensesOutputBuilder {
    /// Appends an item to `lens_summaries`.
    ///
    /// To override the contents of this collection use [`set_lens_summaries`](Self::set_lens_summaries).
    ///
    /// <p>List of lens summaries of available lenses.</p>
    pub fn lens_summaries(mut self, input: crate::types::LensSummary) -> Self {
        let mut v = self.lens_summaries.unwrap_or_default();
        v.push(input);
        self.lens_summaries = ::std::option::Option::Some(v);
        self
    }
    /// <p>List of lens summaries of available lenses.</p>
    pub fn set_lens_summaries(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::LensSummary>>) -> Self {
        self.lens_summaries = input;
        self
    }
    /// <p>List of lens summaries of available lenses.</p>
    pub fn get_lens_summaries(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::LensSummary>> {
        &self.lens_summaries
    }
    /// <p>The token to use to retrieve the next set of results.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The token to use to retrieve the next set of results.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>The token to use to retrieve the next set of results.</p>
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
    /// Consumes the builder and constructs a [`ListLensesOutput`](crate::operation::list_lenses::ListLensesOutput).
    pub fn build(self) -> crate::operation::list_lenses::ListLensesOutput {
        crate::operation::list_lenses::ListLensesOutput {
            lens_summaries: self.lens_summaries,
            next_token: self.next_token,
            _request_id: self._request_id,
        }
    }
}
