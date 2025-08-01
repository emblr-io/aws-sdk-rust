// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteVpcEndpointOutput {
    /// <p>Details about the deleted endpoint.</p>
    pub delete_vpc_endpoint_detail: ::std::option::Option<crate::types::DeleteVpcEndpointDetail>,
    _request_id: Option<String>,
}
impl DeleteVpcEndpointOutput {
    /// <p>Details about the deleted endpoint.</p>
    pub fn delete_vpc_endpoint_detail(&self) -> ::std::option::Option<&crate::types::DeleteVpcEndpointDetail> {
        self.delete_vpc_endpoint_detail.as_ref()
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
    pub(crate) delete_vpc_endpoint_detail: ::std::option::Option<crate::types::DeleteVpcEndpointDetail>,
    _request_id: Option<String>,
}
impl DeleteVpcEndpointOutputBuilder {
    /// <p>Details about the deleted endpoint.</p>
    pub fn delete_vpc_endpoint_detail(mut self, input: crate::types::DeleteVpcEndpointDetail) -> Self {
        self.delete_vpc_endpoint_detail = ::std::option::Option::Some(input);
        self
    }
    /// <p>Details about the deleted endpoint.</p>
    pub fn set_delete_vpc_endpoint_detail(mut self, input: ::std::option::Option<crate::types::DeleteVpcEndpointDetail>) -> Self {
        self.delete_vpc_endpoint_detail = input;
        self
    }
    /// <p>Details about the deleted endpoint.</p>
    pub fn get_delete_vpc_endpoint_detail(&self) -> &::std::option::Option<crate::types::DeleteVpcEndpointDetail> {
        &self.delete_vpc_endpoint_detail
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
            delete_vpc_endpoint_detail: self.delete_vpc_endpoint_detail,
            _request_id: self._request_id,
        }
    }
}
