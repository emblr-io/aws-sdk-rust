// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Represents the result of a list runs request.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListRunsOutput {
    /// <p>Information about the runs.</p>
    pub runs: ::std::option::Option<::std::vec::Vec<crate::types::Run>>,
    /// <p>If the number of items that are returned is significantly large, this is an identifier that is also returned. It can be used in a subsequent call to this operation to return the next set of items in the list.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListRunsOutput {
    /// <p>Information about the runs.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.runs.is_none()`.
    pub fn runs(&self) -> &[crate::types::Run] {
        self.runs.as_deref().unwrap_or_default()
    }
    /// <p>If the number of items that are returned is significantly large, this is an identifier that is also returned. It can be used in a subsequent call to this operation to return the next set of items in the list.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for ListRunsOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl ListRunsOutput {
    /// Creates a new builder-style object to manufacture [`ListRunsOutput`](crate::operation::list_runs::ListRunsOutput).
    pub fn builder() -> crate::operation::list_runs::builders::ListRunsOutputBuilder {
        crate::operation::list_runs::builders::ListRunsOutputBuilder::default()
    }
}

/// A builder for [`ListRunsOutput`](crate::operation::list_runs::ListRunsOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListRunsOutputBuilder {
    pub(crate) runs: ::std::option::Option<::std::vec::Vec<crate::types::Run>>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListRunsOutputBuilder {
    /// Appends an item to `runs`.
    ///
    /// To override the contents of this collection use [`set_runs`](Self::set_runs).
    ///
    /// <p>Information about the runs.</p>
    pub fn runs(mut self, input: crate::types::Run) -> Self {
        let mut v = self.runs.unwrap_or_default();
        v.push(input);
        self.runs = ::std::option::Option::Some(v);
        self
    }
    /// <p>Information about the runs.</p>
    pub fn set_runs(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Run>>) -> Self {
        self.runs = input;
        self
    }
    /// <p>Information about the runs.</p>
    pub fn get_runs(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Run>> {
        &self.runs
    }
    /// <p>If the number of items that are returned is significantly large, this is an identifier that is also returned. It can be used in a subsequent call to this operation to return the next set of items in the list.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>If the number of items that are returned is significantly large, this is an identifier that is also returned. It can be used in a subsequent call to this operation to return the next set of items in the list.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>If the number of items that are returned is significantly large, this is an identifier that is also returned. It can be used in a subsequent call to this operation to return the next set of items in the list.</p>
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
    /// Consumes the builder and constructs a [`ListRunsOutput`](crate::operation::list_runs::ListRunsOutput).
    pub fn build(self) -> crate::operation::list_runs::ListRunsOutput {
        crate::operation::list_runs::ListRunsOutput {
            runs: self.runs,
            next_token: self.next_token,
            _request_id: self._request_id,
        }
    }
}
