// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteVpcEndpointOutput {
    /// <p>Information about the deleted endpoint, including its current status (<code>DELETING</code> or <code>DELETE_FAILED</code>).</p>
    pub vpc_endpoint_summary: ::std::option::Option<crate::types::VpcEndpointSummary>,
    _request_id: Option<String>,
}
impl DeleteVpcEndpointOutput {
    /// <p>Information about the deleted endpoint, including its current status (<code>DELETING</code> or <code>DELETE_FAILED</code>).</p>
    pub fn vpc_endpoint_summary(&self) -> ::std::option::Option<&crate::types::VpcEndpointSummary> {
        self.vpc_endpoint_summary.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for DeleteVpcEndpointOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DeleteVpcEndpointOutput {
    /// Creates a new builder-style object to manufacture [`DeleteVpcEndpointOutput`](crate::operation::delete_vpc_endpoint::DeleteVpcEndpointOutput).
    pub fn builder() -> crate::operation::delete_vpc_endpoint::builders::DeleteVpcEndpointOutputBuilder {
        crate::operation::delete_vpc_endpoint::builders::DeleteVpcEndpointOutputBuilder::default()
    }
}

/// A builder for [`DeleteVpcEndpointOutput`](crate::operation::delete_vpc_endpoint::DeleteVpcEndpointOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeleteVpcEndpointOutputBuilder {
    pub(crate) vpc_endpoint_summary: ::std::option::Option<crate::types::VpcEndpointSummary>,
    _request_id: Option<String>,
}
impl DeleteVpcEndpointOutputBuilder {
    /// <p>Information about the deleted endpoint, including its current status (<code>DELETING</code> or <code>DELETE_FAILED</code>).</p>
    /// This field is required.
    pub fn vpc_endpoint_summary(mut self, input: crate::types::VpcEndpointSummary) -> Self {
        self.vpc_endpoint_summary = ::std::option::Option::Some(input);
        self
    }
    /// <p>Information about the deleted endpoint, including its current status (<code>DELETING</code> or <code>DELETE_FAILED</code>).</p>
    pub fn set_vpc_endpoint_summary(mut self, input: ::std::option::Option<crate::types::VpcEndpointSummary>) -> Self {
        self.vpc_endpoint_summary = input;
        self
    }
    /// <p>Information about the deleted endpoint, including its current status (<code>DELETING</code> or <code>DELETE_FAILED</code>).</p>
    pub fn get_vpc_endpoint_summary(&self) -> &::std::option::Option<crate::types::VpcEndpointSummary> {
        &self.vpc_endpoint_summary
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`DeleteVpcEndpointOutput`](crate::operation::delete_vpc_endpoint::DeleteVpcEndpointOutput).
    pub fn build(self) -> crate::operation::delete_vpc_endpoint::DeleteVpcEndpointOutput {
        crate::operation::delete_vpc_endpoint::DeleteVpcEndpointOutput {
            vpc_endpoint_summary: self.vpc_endpoint_summary,
            _request_id: self._request_id,
        }
    }
}
