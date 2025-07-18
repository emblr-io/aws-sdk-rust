// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeApplicationVersionOutput {
    /// <p>Describes the application, including the application Amazon Resource Name (ARN), status, latest version, and input and output configurations.</p>
    pub application_version_detail: ::std::option::Option<crate::types::ApplicationDetail>,
    _request_id: Option<String>,
}
impl DescribeApplicationVersionOutput {
    /// <p>Describes the application, including the application Amazon Resource Name (ARN), status, latest version, and input and output configurations.</p>
    pub fn application_version_detail(&self) -> ::std::option::Option<&crate::types::ApplicationDetail> {
        self.application_version_detail.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for DescribeApplicationVersionOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DescribeApplicationVersionOutput {
    /// Creates a new builder-style object to manufacture [`DescribeApplicationVersionOutput`](crate::operation::describe_application_version::DescribeApplicationVersionOutput).
    pub fn builder() -> crate::operation::describe_application_version::builders::DescribeApplicationVersionOutputBuilder {
        crate::operation::describe_application_version::builders::DescribeApplicationVersionOutputBuilder::default()
    }
}

/// A builder for [`DescribeApplicationVersionOutput`](crate::operation::describe_application_version::DescribeApplicationVersionOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeApplicationVersionOutputBuilder {
    pub(crate) application_version_detail: ::std::option::Option<crate::types::ApplicationDetail>,
    _request_id: Option<String>,
}
impl DescribeApplicationVersionOutputBuilder {
    /// <p>Describes the application, including the application Amazon Resource Name (ARN), status, latest version, and input and output configurations.</p>
    pub fn application_version_detail(mut self, input: crate::types::ApplicationDetail) -> Self {
        self.application_version_detail = ::std::option::Option::Some(input);
        self
    }
    /// <p>Describes the application, including the application Amazon Resource Name (ARN), status, latest version, and input and output configurations.</p>
    pub fn set_application_version_detail(mut self, input: ::std::option::Option<crate::types::ApplicationDetail>) -> Self {
        self.application_version_detail = input;
        self
    }
    /// <p>Describes the application, including the application Amazon Resource Name (ARN), status, latest version, and input and output configurations.</p>
    pub fn get_application_version_detail(&self) -> &::std::option::Option<crate::types::ApplicationDetail> {
        &self.application_version_detail
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`DescribeApplicationVersionOutput`](crate::operation::describe_application_version::DescribeApplicationVersionOutput).
    pub fn build(self) -> crate::operation::describe_application_version::DescribeApplicationVersionOutput {
        crate::operation::describe_application_version::DescribeApplicationVersionOutput {
            application_version_detail: self.application_version_detail,
            _request_id: self._request_id,
        }
    }
}
