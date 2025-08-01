// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetPrivateGraphEndpointOutput {
    /// <p>The ID of the VPC where the private endpoint is located.</p>
    pub vpc_id: ::std::string::String,
    /// <p>The subnet IDs involved.</p>
    pub subnet_ids: ::std::vec::Vec<::std::string::String>,
    /// <p>The current status of the private endpoint.</p>
    pub status: crate::types::PrivateGraphEndpointStatus,
    /// <p>The ID of the private endpoint.</p>
    pub vpc_endpoint_id: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl GetPrivateGraphEndpointOutput {
    /// <p>The ID of the VPC where the private endpoint is located.</p>
    pub fn vpc_id(&self) -> &str {
        use std::ops::Deref;
        self.vpc_id.deref()
    }
    /// <p>The subnet IDs involved.</p>
    pub fn subnet_ids(&self) -> &[::std::string::String] {
        use std::ops::Deref;
        self.subnet_ids.deref()
    }
    /// <p>The current status of the private endpoint.</p>
    pub fn status(&self) -> &crate::types::PrivateGraphEndpointStatus {
        &self.status
    }
    /// <p>The ID of the private endpoint.</p>
    pub fn vpc_endpoint_id(&self) -> ::std::option::Option<&str> {
        self.vpc_endpoint_id.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for GetPrivateGraphEndpointOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl GetPrivateGraphEndpointOutput {
    /// Creates a new builder-style object to manufacture [`GetPrivateGraphEndpointOutput`](crate::operation::get_private_graph_endpoint::GetPrivateGraphEndpointOutput).
    pub fn builder() -> crate::operation::get_private_graph_endpoint::builders::GetPrivateGraphEndpointOutputBuilder {
        crate::operation::get_private_graph_endpoint::builders::GetPrivateGraphEndpointOutputBuilder::default()
    }
}

/// A builder for [`GetPrivateGraphEndpointOutput`](crate::operation::get_private_graph_endpoint::GetPrivateGraphEndpointOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetPrivateGraphEndpointOutputBuilder {
    pub(crate) vpc_id: ::std::option::Option<::std::string::String>,
    pub(crate) subnet_ids: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) status: ::std::option::Option<crate::types::PrivateGraphEndpointStatus>,
    pub(crate) vpc_endpoint_id: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl GetPrivateGraphEndpointOutputBuilder {
    /// <p>The ID of the VPC where the private endpoint is located.</p>
    /// This field is required.
    pub fn vpc_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.vpc_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the VPC where the private endpoint is located.</p>
    pub fn set_vpc_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.vpc_id = input;
        self
    }
    /// <p>The ID of the VPC where the private endpoint is located.</p>
    pub fn get_vpc_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.vpc_id
    }
    /// Appends an item to `subnet_ids`.
    ///
    /// To override the contents of this collection use [`set_subnet_ids`](Self::set_subnet_ids).
    ///
    /// <p>The subnet IDs involved.</p>
    pub fn subnet_ids(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.subnet_ids.unwrap_or_default();
        v.push(input.into());
        self.subnet_ids = ::std::option::Option::Some(v);
        self
    }
    /// <p>The subnet IDs involved.</p>
    pub fn set_subnet_ids(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.subnet_ids = input;
        self
    }
    /// <p>The subnet IDs involved.</p>
    pub fn get_subnet_ids(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.subnet_ids
    }
    /// <p>The current status of the private endpoint.</p>
    /// This field is required.
    pub fn status(mut self, input: crate::types::PrivateGraphEndpointStatus) -> Self {
        self.status = ::std::option::Option::Some(input);
        self
    }
    /// <p>The current status of the private endpoint.</p>
    pub fn set_status(mut self, input: ::std::option::Option<crate::types::PrivateGraphEndpointStatus>) -> Self {
        self.status = input;
        self
    }
    /// <p>The current status of the private endpoint.</p>
    pub fn get_status(&self) -> &::std::option::Option<crate::types::PrivateGraphEndpointStatus> {
        &self.status
    }
    /// <p>The ID of the private endpoint.</p>
    pub fn vpc_endpoint_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.vpc_endpoint_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the private endpoint.</p>
    pub fn set_vpc_endpoint_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.vpc_endpoint_id = input;
        self
    }
    /// <p>The ID of the private endpoint.</p>
    pub fn get_vpc_endpoint_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.vpc_endpoint_id
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`GetPrivateGraphEndpointOutput`](crate::operation::get_private_graph_endpoint::GetPrivateGraphEndpointOutput).
    /// This method will fail if any of the following fields are not set:
    /// - [`vpc_id`](crate::operation::get_private_graph_endpoint::builders::GetPrivateGraphEndpointOutputBuilder::vpc_id)
    /// - [`subnet_ids`](crate::operation::get_private_graph_endpoint::builders::GetPrivateGraphEndpointOutputBuilder::subnet_ids)
    /// - [`status`](crate::operation::get_private_graph_endpoint::builders::GetPrivateGraphEndpointOutputBuilder::status)
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::get_private_graph_endpoint::GetPrivateGraphEndpointOutput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::get_private_graph_endpoint::GetPrivateGraphEndpointOutput {
            vpc_id: self.vpc_id.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "vpc_id",
                    "vpc_id was not specified but it is required when building GetPrivateGraphEndpointOutput",
                )
            })?,
            subnet_ids: self.subnet_ids.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "subnet_ids",
                    "subnet_ids was not specified but it is required when building GetPrivateGraphEndpointOutput",
                )
            })?,
            status: self.status.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "status",
                    "status was not specified but it is required when building GetPrivateGraphEndpointOutput",
                )
            })?,
            vpc_endpoint_id: self.vpc_endpoint_id,
            _request_id: self._request_id,
        })
    }
}
