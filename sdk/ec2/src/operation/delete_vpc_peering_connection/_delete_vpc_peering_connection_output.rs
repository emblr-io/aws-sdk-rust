// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteVpcPeeringConnectionOutput {
    /// <p>Returns <code>true</code> if the request succeeds; otherwise, it returns an error.</p>
    pub r#return: ::std::option::Option<bool>,
    _request_id: Option<String>,
}
impl DeleteVpcPeeringConnectionOutput {
    /// <p>Returns <code>true</code> if the request succeeds; otherwise, it returns an error.</p>
    pub fn r#return(&self) -> ::std::option::Option<bool> {
        self.r#return
    }
}
impl ::aws_types::request_id::RequestId for DeleteVpcPeeringConnectionOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DeleteVpcPeeringConnectionOutput {
    /// Creates a new builder-style object to manufacture [`DeleteVpcPeeringConnectionOutput`](crate::operation::delete_vpc_peering_connection::DeleteVpcPeeringConnectionOutput).
    pub fn builder() -> crate::operation::delete_vpc_peering_connection::builders::DeleteVpcPeeringConnectionOutputBuilder {
        crate::operation::delete_vpc_peering_connection::builders::DeleteVpcPeeringConnectionOutputBuilder::default()
    }
}

/// A builder for [`DeleteVpcPeeringConnectionOutput`](crate::operation::delete_vpc_peering_connection::DeleteVpcPeeringConnectionOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeleteVpcPeeringConnectionOutputBuilder {
    pub(crate) r#return: ::std::option::Option<bool>,
    _request_id: Option<String>,
}
impl DeleteVpcPeeringConnectionOutputBuilder {
    /// <p>Returns <code>true</code> if the request succeeds; otherwise, it returns an error.</p>
    pub fn r#return(mut self, input: bool) -> Self {
        self.r#return = ::std::option::Option::Some(input);
        self
    }
    /// <p>Returns <code>true</code> if the request succeeds; otherwise, it returns an error.</p>
    pub fn set_return(mut self, input: ::std::option::Option<bool>) -> Self {
        self.r#return = input;
        self
    }
    /// <p>Returns <code>true</code> if the request succeeds; otherwise, it returns an error.</p>
    pub fn get_return(&self) -> &::std::option::Option<bool> {
        &self.r#return
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`DeleteVpcPeeringConnectionOutput`](crate::operation::delete_vpc_peering_connection::DeleteVpcPeeringConnectionOutput).
    pub fn build(self) -> crate::operation::delete_vpc_peering_connection::DeleteVpcPeeringConnectionOutput {
        crate::operation::delete_vpc_peering_connection::DeleteVpcPeeringConnectionOutput {
            r#return: self.r#return,
            _request_id: self._request_id,
        }
    }
}
