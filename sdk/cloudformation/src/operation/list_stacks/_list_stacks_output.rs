// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The output for <code>ListStacks</code> action.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListStacksOutput {
    /// <p>A list of <code>StackSummary</code> structures that contains information about the specified stacks.</p>
    pub stack_summaries: ::std::option::Option<::std::vec::Vec<crate::types::StackSummary>>,
    /// <p>If the output exceeds 1 MB in size, a string that identifies the next page of stacks. If no additional page exists, this value is null.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListStacksOutput {
    /// <p>A list of <code>StackSummary</code> structures that contains information about the specified stacks.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.stack_summaries.is_none()`.
    pub fn stack_summaries(&self) -> &[crate::types::StackSummary] {
        self.stack_summaries.as_deref().unwrap_or_default()
    }
    /// <p>If the output exceeds 1 MB in size, a string that identifies the next page of stacks. If no additional page exists, this value is null.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for ListStacksOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl ListStacksOutput {
    /// Creates a new builder-style object to manufacture [`ListStacksOutput`](crate::operation::list_stacks::ListStacksOutput).
    pub fn builder() -> crate::operation::list_stacks::builders::ListStacksOutputBuilder {
        crate::operation::list_stacks::builders::ListStacksOutputBuilder::default()
    }
}

/// A builder for [`ListStacksOutput`](crate::operation::list_stacks::ListStacksOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListStacksOutputBuilder {
    pub(crate) stack_summaries: ::std::option::Option<::std::vec::Vec<crate::types::StackSummary>>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListStacksOutputBuilder {
    /// Appends an item to `stack_summaries`.
    ///
    /// To override the contents of this collection use [`set_stack_summaries`](Self::set_stack_summaries).
    ///
    /// <p>A list of <code>StackSummary</code> structures that contains information about the specified stacks.</p>
    pub fn stack_summaries(mut self, input: crate::types::StackSummary) -> Self {
        let mut v = self.stack_summaries.unwrap_or_default();
        v.push(input);
        self.stack_summaries = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of <code>StackSummary</code> structures that contains information about the specified stacks.</p>
    pub fn set_stack_summaries(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::StackSummary>>) -> Self {
        self.stack_summaries = input;
        self
    }
    /// <p>A list of <code>StackSummary</code> structures that contains information about the specified stacks.</p>
    pub fn get_stack_summaries(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::StackSummary>> {
        &self.stack_summaries
    }
    /// <p>If the output exceeds 1 MB in size, a string that identifies the next page of stacks. If no additional page exists, this value is null.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>If the output exceeds 1 MB in size, a string that identifies the next page of stacks. If no additional page exists, this value is null.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>If the output exceeds 1 MB in size, a string that identifies the next page of stacks. If no additional page exists, this value is null.</p>
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
    /// Consumes the builder and constructs a [`ListStacksOutput`](crate::operation::list_stacks::ListStacksOutput).
    pub fn build(self) -> crate::operation::list_stacks::ListStacksOutput {
        crate::operation::list_stacks::ListStacksOutput {
            stack_summaries: self.stack_summaries,
            next_token: self.next_token,
            _request_id: self._request_id,
        }
    }
}
