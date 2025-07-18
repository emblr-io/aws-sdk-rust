// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeApplicationStateOutput {
    /// <p>Status of the application - Not Started, In-Progress, Complete.</p>
    pub application_status: ::std::option::Option<crate::types::ApplicationStatus>,
    /// <p>The timestamp when the application status was last updated.</p>
    pub last_updated_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    _request_id: Option<String>,
}
impl DescribeApplicationStateOutput {
    /// <p>Status of the application - Not Started, In-Progress, Complete.</p>
    pub fn application_status(&self) -> ::std::option::Option<&crate::types::ApplicationStatus> {
        self.application_status.as_ref()
    }
    /// <p>The timestamp when the application status was last updated.</p>
    pub fn last_updated_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.last_updated_time.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for DescribeApplicationStateOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DescribeApplicationStateOutput {
    /// Creates a new builder-style object to manufacture [`DescribeApplicationStateOutput`](crate::operation::describe_application_state::DescribeApplicationStateOutput).
    pub fn builder() -> crate::operation::describe_application_state::builders::DescribeApplicationStateOutputBuilder {
        crate::operation::describe_application_state::builders::DescribeApplicationStateOutputBuilder::default()
    }
}

/// A builder for [`DescribeApplicationStateOutput`](crate::operation::describe_application_state::DescribeApplicationStateOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeApplicationStateOutputBuilder {
    pub(crate) application_status: ::std::option::Option<crate::types::ApplicationStatus>,
    pub(crate) last_updated_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    _request_id: Option<String>,
}
impl DescribeApplicationStateOutputBuilder {
    /// <p>Status of the application - Not Started, In-Progress, Complete.</p>
    pub fn application_status(mut self, input: crate::types::ApplicationStatus) -> Self {
        self.application_status = ::std::option::Option::Some(input);
        self
    }
    /// <p>Status of the application - Not Started, In-Progress, Complete.</p>
    pub fn set_application_status(mut self, input: ::std::option::Option<crate::types::ApplicationStatus>) -> Self {
        self.application_status = input;
        self
    }
    /// <p>Status of the application - Not Started, In-Progress, Complete.</p>
    pub fn get_application_status(&self) -> &::std::option::Option<crate::types::ApplicationStatus> {
        &self.application_status
    }
    /// <p>The timestamp when the application status was last updated.</p>
    pub fn last_updated_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.last_updated_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The timestamp when the application status was last updated.</p>
    pub fn set_last_updated_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.last_updated_time = input;
        self
    }
    /// <p>The timestamp when the application status was last updated.</p>
    pub fn get_last_updated_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.last_updated_time
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`DescribeApplicationStateOutput`](crate::operation::describe_application_state::DescribeApplicationStateOutput).
    pub fn build(self) -> crate::operation::describe_application_state::DescribeApplicationStateOutput {
        crate::operation::describe_application_state::DescribeApplicationStateOutput {
            application_status: self.application_status,
            last_updated_time: self.last_updated_time,
            _request_id: self._request_id,
        }
    }
}
