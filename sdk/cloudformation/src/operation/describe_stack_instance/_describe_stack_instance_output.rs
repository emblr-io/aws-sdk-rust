// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeStackInstanceOutput {
    /// <p>The stack instance that matches the specified request parameters.</p>
    pub stack_instance: ::std::option::Option<crate::types::StackInstance>,
    _request_id: Option<String>,
}
impl DescribeStackInstanceOutput {
    /// <p>The stack instance that matches the specified request parameters.</p>
    pub fn stack_instance(&self) -> ::std::option::Option<&crate::types::StackInstance> {
        self.stack_instance.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for DescribeStackInstanceOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DescribeStackInstanceOutput {
    /// Creates a new builder-style object to manufacture [`DescribeStackInstanceOutput`](crate::operation::describe_stack_instance::DescribeStackInstanceOutput).
    pub fn builder() -> crate::operation::describe_stack_instance::builders::DescribeStackInstanceOutputBuilder {
        crate::operation::describe_stack_instance::builders::DescribeStackInstanceOutputBuilder::default()
    }
}

/// A builder for [`DescribeStackInstanceOutput`](crate::operation::describe_stack_instance::DescribeStackInstanceOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeStackInstanceOutputBuilder {
    pub(crate) stack_instance: ::std::option::Option<crate::types::StackInstance>,
    _request_id: Option<String>,
}
impl DescribeStackInstanceOutputBuilder {
    /// <p>The stack instance that matches the specified request parameters.</p>
    pub fn stack_instance(mut self, input: crate::types::StackInstance) -> Self {
        self.stack_instance = ::std::option::Option::Some(input);
        self
    }
    /// <p>The stack instance that matches the specified request parameters.</p>
    pub fn set_stack_instance(mut self, input: ::std::option::Option<crate::types::StackInstance>) -> Self {
        self.stack_instance = input;
        self
    }
    /// <p>The stack instance that matches the specified request parameters.</p>
    pub fn get_stack_instance(&self) -> &::std::option::Option<crate::types::StackInstance> {
        &self.stack_instance
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`DescribeStackInstanceOutput`](crate::operation::describe_stack_instance::DescribeStackInstanceOutput).
    pub fn build(self) -> crate::operation::describe_stack_instance::DescribeStackInstanceOutput {
        crate::operation::describe_stack_instance::DescribeStackInstanceOutput {
            stack_instance: self.stack_instance,
            _request_id: self._request_id,
        }
    }
}
