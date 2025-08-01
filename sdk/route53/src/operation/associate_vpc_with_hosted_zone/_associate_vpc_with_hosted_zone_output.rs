// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A complex type that contains the response information for the <code>AssociateVPCWithHostedZone</code> request.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AssociateVpcWithHostedZoneOutput {
    /// <p>A complex type that describes the changes made to your hosted zone.</p>
    pub change_info: ::std::option::Option<crate::types::ChangeInfo>,
    _request_id: Option<String>,
}
impl AssociateVpcWithHostedZoneOutput {
    /// <p>A complex type that describes the changes made to your hosted zone.</p>
    pub fn change_info(&self) -> ::std::option::Option<&crate::types::ChangeInfo> {
        self.change_info.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for AssociateVpcWithHostedZoneOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl AssociateVpcWithHostedZoneOutput {
    /// Creates a new builder-style object to manufacture [`AssociateVpcWithHostedZoneOutput`](crate::operation::associate_vpc_with_hosted_zone::AssociateVpcWithHostedZoneOutput).
    pub fn builder() -> crate::operation::associate_vpc_with_hosted_zone::builders::AssociateVpcWithHostedZoneOutputBuilder {
        crate::operation::associate_vpc_with_hosted_zone::builders::AssociateVpcWithHostedZoneOutputBuilder::default()
    }
}

/// A builder for [`AssociateVpcWithHostedZoneOutput`](crate::operation::associate_vpc_with_hosted_zone::AssociateVpcWithHostedZoneOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AssociateVpcWithHostedZoneOutputBuilder {
    pub(crate) change_info: ::std::option::Option<crate::types::ChangeInfo>,
    _request_id: Option<String>,
}
impl AssociateVpcWithHostedZoneOutputBuilder {
    /// <p>A complex type that describes the changes made to your hosted zone.</p>
    /// This field is required.
    pub fn change_info(mut self, input: crate::types::ChangeInfo) -> Self {
        self.change_info = ::std::option::Option::Some(input);
        self
    }
    /// <p>A complex type that describes the changes made to your hosted zone.</p>
    pub fn set_change_info(mut self, input: ::std::option::Option<crate::types::ChangeInfo>) -> Self {
        self.change_info = input;
        self
    }
    /// <p>A complex type that describes the changes made to your hosted zone.</p>
    pub fn get_change_info(&self) -> &::std::option::Option<crate::types::ChangeInfo> {
        &self.change_info
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`AssociateVpcWithHostedZoneOutput`](crate::operation::associate_vpc_with_hosted_zone::AssociateVpcWithHostedZoneOutput).
    pub fn build(self) -> crate::operation::associate_vpc_with_hosted_zone::AssociateVpcWithHostedZoneOutput {
        crate::operation::associate_vpc_with_hosted_zone::AssociateVpcWithHostedZoneOutput {
            change_info: self.change_info,
            _request_id: self._request_id,
        }
    }
}
