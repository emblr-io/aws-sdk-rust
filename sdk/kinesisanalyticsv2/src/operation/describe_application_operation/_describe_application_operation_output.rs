// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// Provides details of the operation corresponding to the operation-ID on a Managed Service for Apache Flink application
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeApplicationOperationOutput {
    /// Provides a description of the operation, such as the operation-type and status
    pub application_operation_info_details: ::std::option::Option<crate::types::ApplicationOperationInfoDetails>,
    _request_id: Option<String>,
}
impl DescribeApplicationOperationOutput {
    /// Provides a description of the operation, such as the operation-type and status
    pub fn application_operation_info_details(&self) -> ::std::option::Option<&crate::types::ApplicationOperationInfoDetails> {
        self.application_operation_info_details.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for DescribeApplicationOperationOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DescribeApplicationOperationOutput {
    /// Creates a new builder-style object to manufacture [`DescribeApplicationOperationOutput`](crate::operation::describe_application_operation::DescribeApplicationOperationOutput).
    pub fn builder() -> crate::operation::describe_application_operation::builders::DescribeApplicationOperationOutputBuilder {
        crate::operation::describe_application_operation::builders::DescribeApplicationOperationOutputBuilder::default()
    }
}

/// A builder for [`DescribeApplicationOperationOutput`](crate::operation::describe_application_operation::DescribeApplicationOperationOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeApplicationOperationOutputBuilder {
    pub(crate) application_operation_info_details: ::std::option::Option<crate::types::ApplicationOperationInfoDetails>,
    _request_id: Option<String>,
}
impl DescribeApplicationOperationOutputBuilder {
    /// Provides a description of the operation, such as the operation-type and status
    pub fn application_operation_info_details(mut self, input: crate::types::ApplicationOperationInfoDetails) -> Self {
        self.application_operation_info_details = ::std::option::Option::Some(input);
        self
    }
    /// Provides a description of the operation, such as the operation-type and status
    pub fn set_application_operation_info_details(mut self, input: ::std::option::Option<crate::types::ApplicationOperationInfoDetails>) -> Self {
        self.application_operation_info_details = input;
        self
    }
    /// Provides a description of the operation, such as the operation-type and status
    pub fn get_application_operation_info_details(&self) -> &::std::option::Option<crate::types::ApplicationOperationInfoDetails> {
        &self.application_operation_info_details
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`DescribeApplicationOperationOutput`](crate::operation::describe_application_operation::DescribeApplicationOperationOutput).
    pub fn build(self) -> crate::operation::describe_application_operation::DescribeApplicationOperationOutput {
        crate::operation::describe_application_operation::DescribeApplicationOperationOutput {
            application_operation_info_details: self.application_operation_info_details,
            _request_id: self._request_id,
        }
    }
}
