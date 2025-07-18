// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeComputeOutput {
    /// <p>The set of properties for the requested compute resource.</p>
    pub compute: ::std::option::Option<crate::types::Compute>,
    _request_id: Option<String>,
}
impl DescribeComputeOutput {
    /// <p>The set of properties for the requested compute resource.</p>
    pub fn compute(&self) -> ::std::option::Option<&crate::types::Compute> {
        self.compute.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for DescribeComputeOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DescribeComputeOutput {
    /// Creates a new builder-style object to manufacture [`DescribeComputeOutput`](crate::operation::describe_compute::DescribeComputeOutput).
    pub fn builder() -> crate::operation::describe_compute::builders::DescribeComputeOutputBuilder {
        crate::operation::describe_compute::builders::DescribeComputeOutputBuilder::default()
    }
}

/// A builder for [`DescribeComputeOutput`](crate::operation::describe_compute::DescribeComputeOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeComputeOutputBuilder {
    pub(crate) compute: ::std::option::Option<crate::types::Compute>,
    _request_id: Option<String>,
}
impl DescribeComputeOutputBuilder {
    /// <p>The set of properties for the requested compute resource.</p>
    pub fn compute(mut self, input: crate::types::Compute) -> Self {
        self.compute = ::std::option::Option::Some(input);
        self
    }
    /// <p>The set of properties for the requested compute resource.</p>
    pub fn set_compute(mut self, input: ::std::option::Option<crate::types::Compute>) -> Self {
        self.compute = input;
        self
    }
    /// <p>The set of properties for the requested compute resource.</p>
    pub fn get_compute(&self) -> &::std::option::Option<crate::types::Compute> {
        &self.compute
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`DescribeComputeOutput`](crate::operation::describe_compute::DescribeComputeOutput).
    pub fn build(self) -> crate::operation::describe_compute::DescribeComputeOutput {
        crate::operation::describe_compute::DescribeComputeOutput {
            compute: self.compute,
            _request_id: self._request_id,
        }
    }
}
