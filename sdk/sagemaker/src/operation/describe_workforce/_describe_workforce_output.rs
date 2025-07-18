// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeWorkforceOutput {
    /// <p>A single private workforce, which is automatically created when you create your first private work team. You can create one private work force in each Amazon Web Services Region. By default, any workforce-related API operation used in a specific region will apply to the workforce created in that region. To learn how to create a private workforce, see <a href="https://docs.aws.amazon.com/sagemaker/latest/dg/sms-workforce-create-private.html">Create a Private Workforce</a>.</p>
    pub workforce: ::std::option::Option<crate::types::Workforce>,
    _request_id: Option<String>,
}
impl DescribeWorkforceOutput {
    /// <p>A single private workforce, which is automatically created when you create your first private work team. You can create one private work force in each Amazon Web Services Region. By default, any workforce-related API operation used in a specific region will apply to the workforce created in that region. To learn how to create a private workforce, see <a href="https://docs.aws.amazon.com/sagemaker/latest/dg/sms-workforce-create-private.html">Create a Private Workforce</a>.</p>
    pub fn workforce(&self) -> ::std::option::Option<&crate::types::Workforce> {
        self.workforce.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for DescribeWorkforceOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DescribeWorkforceOutput {
    /// Creates a new builder-style object to manufacture [`DescribeWorkforceOutput`](crate::operation::describe_workforce::DescribeWorkforceOutput).
    pub fn builder() -> crate::operation::describe_workforce::builders::DescribeWorkforceOutputBuilder {
        crate::operation::describe_workforce::builders::DescribeWorkforceOutputBuilder::default()
    }
}

/// A builder for [`DescribeWorkforceOutput`](crate::operation::describe_workforce::DescribeWorkforceOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeWorkforceOutputBuilder {
    pub(crate) workforce: ::std::option::Option<crate::types::Workforce>,
    _request_id: Option<String>,
}
impl DescribeWorkforceOutputBuilder {
    /// <p>A single private workforce, which is automatically created when you create your first private work team. You can create one private work force in each Amazon Web Services Region. By default, any workforce-related API operation used in a specific region will apply to the workforce created in that region. To learn how to create a private workforce, see <a href="https://docs.aws.amazon.com/sagemaker/latest/dg/sms-workforce-create-private.html">Create a Private Workforce</a>.</p>
    /// This field is required.
    pub fn workforce(mut self, input: crate::types::Workforce) -> Self {
        self.workforce = ::std::option::Option::Some(input);
        self
    }
    /// <p>A single private workforce, which is automatically created when you create your first private work team. You can create one private work force in each Amazon Web Services Region. By default, any workforce-related API operation used in a specific region will apply to the workforce created in that region. To learn how to create a private workforce, see <a href="https://docs.aws.amazon.com/sagemaker/latest/dg/sms-workforce-create-private.html">Create a Private Workforce</a>.</p>
    pub fn set_workforce(mut self, input: ::std::option::Option<crate::types::Workforce>) -> Self {
        self.workforce = input;
        self
    }
    /// <p>A single private workforce, which is automatically created when you create your first private work team. You can create one private work force in each Amazon Web Services Region. By default, any workforce-related API operation used in a specific region will apply to the workforce created in that region. To learn how to create a private workforce, see <a href="https://docs.aws.amazon.com/sagemaker/latest/dg/sms-workforce-create-private.html">Create a Private Workforce</a>.</p>
    pub fn get_workforce(&self) -> &::std::option::Option<crate::types::Workforce> {
        &self.workforce
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`DescribeWorkforceOutput`](crate::operation::describe_workforce::DescribeWorkforceOutput).
    pub fn build(self) -> crate::operation::describe_workforce::DescribeWorkforceOutput {
        crate::operation::describe_workforce::DescribeWorkforceOutput {
            workforce: self.workforce,
            _request_id: self._request_id,
        }
    }
}
