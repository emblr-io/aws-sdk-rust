// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The output for a <code>DescribeStacks</code> action.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeStacksOutput {
    /// <p>A list of stack structures.</p>
    pub stacks: ::std::option::Option<::std::vec::Vec<crate::types::Stack>>,
    /// <p>If the output exceeds 1 MB in size, a string that identifies the next page of stacks. If no additional page exists, this value is null.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl DescribeStacksOutput {
    /// <p>A list of stack structures.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.stacks.is_none()`.
    pub fn stacks(&self) -> &[crate::types::Stack] {
        self.stacks.as_deref().unwrap_or_default()
    }
    /// <p>If the output exceeds 1 MB in size, a string that identifies the next page of stacks. If no additional page exists, this value is null.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for DescribeStacksOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DescribeStacksOutput {
    /// Creates a new builder-style object to manufacture [`DescribeStacksOutput`](crate::operation::describe_stacks::DescribeStacksOutput).
    pub fn builder() -> crate::operation::describe_stacks::builders::DescribeStacksOutputBuilder {
        crate::operation::describe_stacks::builders::DescribeStacksOutputBuilder::default()
    }
}

/// A builder for [`DescribeStacksOutput`](crate::operation::describe_stacks::DescribeStacksOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeStacksOutputBuilder {
    pub(crate) stacks: ::std::option::Option<::std::vec::Vec<crate::types::Stack>>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl DescribeStacksOutputBuilder {
    /// Appends an item to `stacks`.
    ///
    /// To override the contents of this collection use [`set_stacks`](Self::set_stacks).
    ///
    /// <p>A list of stack structures.</p>
    pub fn stacks(mut self, input: crate::types::Stack) -> Self {
        let mut v = self.stacks.unwrap_or_default();
        v.push(input);
        self.stacks = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of stack structures.</p>
    pub fn set_stacks(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Stack>>) -> Self {
        self.stacks = input;
        self
    }
    /// <p>A list of stack structures.</p>
    pub fn get_stacks(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Stack>> {
        &self.stacks
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
    /// Consumes the builder and constructs a [`DescribeStacksOutput`](crate::operation::describe_stacks::DescribeStacksOutput).
    pub fn build(self) -> crate::operation::describe_stacks::DescribeStacksOutput {
        crate::operation::describe_stacks::DescribeStacksOutput {
            stacks: self.stacks,
            next_token: self.next_token,
            _request_id: self._request_id,
        }
    }
}
