// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListPipelinesOutput {
    /// <p>When <code>nextToken</code> is returned, there are more results available. The value of <code>nextToken</code> is a unique pagination token for each page. Make the call again using the returned token to retrieve the next page.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    /// <p>A list of all existing Data Prepper pipelines.</p>
    pub pipelines: ::std::option::Option<::std::vec::Vec<crate::types::PipelineSummary>>,
    _request_id: Option<String>,
}
impl ListPipelinesOutput {
    /// <p>When <code>nextToken</code> is returned, there are more results available. The value of <code>nextToken</code> is a unique pagination token for each page. Make the call again using the returned token to retrieve the next page.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
    /// <p>A list of all existing Data Prepper pipelines.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.pipelines.is_none()`.
    pub fn pipelines(&self) -> &[crate::types::PipelineSummary] {
        self.pipelines.as_deref().unwrap_or_default()
    }
}
impl ::aws_types::request_id::RequestId for ListPipelinesOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl ListPipelinesOutput {
    /// Creates a new builder-style object to manufacture [`ListPipelinesOutput`](crate::operation::list_pipelines::ListPipelinesOutput).
    pub fn builder() -> crate::operation::list_pipelines::builders::ListPipelinesOutputBuilder {
        crate::operation::list_pipelines::builders::ListPipelinesOutputBuilder::default()
    }
}

/// A builder for [`ListPipelinesOutput`](crate::operation::list_pipelines::ListPipelinesOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListPipelinesOutputBuilder {
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    pub(crate) pipelines: ::std::option::Option<::std::vec::Vec<crate::types::PipelineSummary>>,
    _request_id: Option<String>,
}
impl ListPipelinesOutputBuilder {
    /// <p>When <code>nextToken</code> is returned, there are more results available. The value of <code>nextToken</code> is a unique pagination token for each page. Make the call again using the returned token to retrieve the next page.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>When <code>nextToken</code> is returned, there are more results available. The value of <code>nextToken</code> is a unique pagination token for each page. Make the call again using the returned token to retrieve the next page.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>When <code>nextToken</code> is returned, there are more results available. The value of <code>nextToken</code> is a unique pagination token for each page. Make the call again using the returned token to retrieve the next page.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// Appends an item to `pipelines`.
    ///
    /// To override the contents of this collection use [`set_pipelines`](Self::set_pipelines).
    ///
    /// <p>A list of all existing Data Prepper pipelines.</p>
    pub fn pipelines(mut self, input: crate::types::PipelineSummary) -> Self {
        let mut v = self.pipelines.unwrap_or_default();
        v.push(input);
        self.pipelines = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of all existing Data Prepper pipelines.</p>
    pub fn set_pipelines(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::PipelineSummary>>) -> Self {
        self.pipelines = input;
        self
    }
    /// <p>A list of all existing Data Prepper pipelines.</p>
    pub fn get_pipelines(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::PipelineSummary>> {
        &self.pipelines
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`ListPipelinesOutput`](crate::operation::list_pipelines::ListPipelinesOutput).
    pub fn build(self) -> crate::operation::list_pipelines::ListPipelinesOutput {
        crate::operation::list_pipelines::ListPipelinesOutput {
            next_token: self.next_token,
            pipelines: self.pipelines,
            _request_id: self._request_id,
        }
    }
}
