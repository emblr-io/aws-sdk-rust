// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListCopyJobsOutput {
    /// <p>An array of structures containing metadata about your copy jobs returned in JSON format.</p>
    pub copy_jobs: ::std::option::Option<::std::vec::Vec<crate::types::CopyJob>>,
    /// <p>The next item following a partial list of returned items. For example, if a request is made to return MaxResults number of items, NextToken allows you to return more items in your list starting at the location pointed to by the next token.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListCopyJobsOutput {
    /// <p>An array of structures containing metadata about your copy jobs returned in JSON format.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.copy_jobs.is_none()`.
    pub fn copy_jobs(&self) -> &[crate::types::CopyJob] {
        self.copy_jobs.as_deref().unwrap_or_default()
    }
    /// <p>The next item following a partial list of returned items. For example, if a request is made to return MaxResults number of items, NextToken allows you to return more items in your list starting at the location pointed to by the next token.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for ListCopyJobsOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl ListCopyJobsOutput {
    /// Creates a new builder-style object to manufacture [`ListCopyJobsOutput`](crate::operation::list_copy_jobs::ListCopyJobsOutput).
    pub fn builder() -> crate::operation::list_copy_jobs::builders::ListCopyJobsOutputBuilder {
        crate::operation::list_copy_jobs::builders::ListCopyJobsOutputBuilder::default()
    }
}

/// A builder for [`ListCopyJobsOutput`](crate::operation::list_copy_jobs::ListCopyJobsOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListCopyJobsOutputBuilder {
    pub(crate) copy_jobs: ::std::option::Option<::std::vec::Vec<crate::types::CopyJob>>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListCopyJobsOutputBuilder {
    /// Appends an item to `copy_jobs`.
    ///
    /// To override the contents of this collection use [`set_copy_jobs`](Self::set_copy_jobs).
    ///
    /// <p>An array of structures containing metadata about your copy jobs returned in JSON format.</p>
    pub fn copy_jobs(mut self, input: crate::types::CopyJob) -> Self {
        let mut v = self.copy_jobs.unwrap_or_default();
        v.push(input);
        self.copy_jobs = ::std::option::Option::Some(v);
        self
    }
    /// <p>An array of structures containing metadata about your copy jobs returned in JSON format.</p>
    pub fn set_copy_jobs(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::CopyJob>>) -> Self {
        self.copy_jobs = input;
        self
    }
    /// <p>An array of structures containing metadata about your copy jobs returned in JSON format.</p>
    pub fn get_copy_jobs(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::CopyJob>> {
        &self.copy_jobs
    }
    /// <p>The next item following a partial list of returned items. For example, if a request is made to return MaxResults number of items, NextToken allows you to return more items in your list starting at the location pointed to by the next token.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The next item following a partial list of returned items. For example, if a request is made to return MaxResults number of items, NextToken allows you to return more items in your list starting at the location pointed to by the next token.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>The next item following a partial list of returned items. For example, if a request is made to return MaxResults number of items, NextToken allows you to return more items in your list starting at the location pointed to by the next token.</p>
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
    /// Consumes the builder and constructs a [`ListCopyJobsOutput`](crate::operation::list_copy_jobs::ListCopyJobsOutput).
    pub fn build(self) -> crate::operation::list_copy_jobs::ListCopyJobsOutput {
        crate::operation::list_copy_jobs::ListCopyJobsOutput {
            copy_jobs: self.copy_jobs,
            next_token: self.next_token,
            _request_id: self._request_id,
        }
    }
}
