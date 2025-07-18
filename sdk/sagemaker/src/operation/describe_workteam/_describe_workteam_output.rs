// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeWorkteamOutput {
    /// <p>A <code>Workteam</code> instance that contains information about the work team.</p>
    pub workteam: ::std::option::Option<crate::types::Workteam>,
    _request_id: Option<String>,
}
impl DescribeWorkteamOutput {
    /// <p>A <code>Workteam</code> instance that contains information about the work team.</p>
    pub fn workteam(&self) -> ::std::option::Option<&crate::types::Workteam> {
        self.workteam.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for DescribeWorkteamOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DescribeWorkteamOutput {
    /// Creates a new builder-style object to manufacture [`DescribeWorkteamOutput`](crate::operation::describe_workteam::DescribeWorkteamOutput).
    pub fn builder() -> crate::operation::describe_workteam::builders::DescribeWorkteamOutputBuilder {
        crate::operation::describe_workteam::builders::DescribeWorkteamOutputBuilder::default()
    }
}

/// A builder for [`DescribeWorkteamOutput`](crate::operation::describe_workteam::DescribeWorkteamOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeWorkteamOutputBuilder {
    pub(crate) workteam: ::std::option::Option<crate::types::Workteam>,
    _request_id: Option<String>,
}
impl DescribeWorkteamOutputBuilder {
    /// <p>A <code>Workteam</code> instance that contains information about the work team.</p>
    /// This field is required.
    pub fn workteam(mut self, input: crate::types::Workteam) -> Self {
        self.workteam = ::std::option::Option::Some(input);
        self
    }
    /// <p>A <code>Workteam</code> instance that contains information about the work team.</p>
    pub fn set_workteam(mut self, input: ::std::option::Option<crate::types::Workteam>) -> Self {
        self.workteam = input;
        self
    }
    /// <p>A <code>Workteam</code> instance that contains information about the work team.</p>
    pub fn get_workteam(&self) -> &::std::option::Option<crate::types::Workteam> {
        &self.workteam
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`DescribeWorkteamOutput`](crate::operation::describe_workteam::DescribeWorkteamOutput).
    pub fn build(self) -> crate::operation::describe_workteam::DescribeWorkteamOutput {
        crate::operation::describe_workteam::DescribeWorkteamOutput {
            workteam: self.workteam,
            _request_id: self._request_id,
        }
    }
}
