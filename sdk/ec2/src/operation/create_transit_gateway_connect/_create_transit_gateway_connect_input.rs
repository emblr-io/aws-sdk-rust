// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateTransitGatewayConnectInput {
    /// <p>The ID of the transit gateway attachment. You can specify a VPC attachment or Amazon Web Services Direct Connect attachment.</p>
    pub transport_transit_gateway_attachment_id: ::std::option::Option<::std::string::String>,
    /// <p>The Connect attachment options.</p>
    pub options: ::std::option::Option<crate::types::CreateTransitGatewayConnectRequestOptions>,
    /// <p>The tags to apply to the Connect attachment.</p>
    pub tag_specifications: ::std::option::Option<::std::vec::Vec<crate::types::TagSpecification>>,
    /// <p>Checks whether you have the required permissions for the action, without actually making the request, and provides an error response. If you have the required permissions, the error response is <code>DryRunOperation</code>. Otherwise, it is <code>UnauthorizedOperation</code>.</p>
    pub dry_run: ::std::option::Option<bool>,
}
impl CreateTransitGatewayConnectInput {
    /// <p>The ID of the transit gateway attachment. You can specify a VPC attachment or Amazon Web Services Direct Connect attachment.</p>
    pub fn transport_transit_gateway_attachment_id(&self) -> ::std::option::Option<&str> {
        self.transport_transit_gateway_attachment_id.as_deref()
    }
    /// <p>The Connect attachment options.</p>
    pub fn options(&self) -> ::std::option::Option<&crate::types::CreateTransitGatewayConnectRequestOptions> {
        self.options.as_ref()
    }
    /// <p>The tags to apply to the Connect attachment.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.tag_specifications.is_none()`.
    pub fn tag_specifications(&self) -> &[crate::types::TagSpecification] {
        self.tag_specifications.as_deref().unwrap_or_default()
    }
    /// <p>Checks whether you have the required permissions for the action, without actually making the request, and provides an error response. If you have the required permissions, the error response is <code>DryRunOperation</code>. Otherwise, it is <code>UnauthorizedOperation</code>.</p>
    pub fn dry_run(&self) -> ::std::option::Option<bool> {
        self.dry_run
    }
}
impl CreateTransitGatewayConnectInput {
    /// Creates a new builder-style object to manufacture [`CreateTransitGatewayConnectInput`](crate::operation::create_transit_gateway_connect::CreateTransitGatewayConnectInput).
    pub fn builder() -> crate::operation::create_transit_gateway_connect::builders::CreateTransitGatewayConnectInputBuilder {
        crate::operation::create_transit_gateway_connect::builders::CreateTransitGatewayConnectInputBuilder::default()
    }
}

/// A builder for [`CreateTransitGatewayConnectInput`](crate::operation::create_transit_gateway_connect::CreateTransitGatewayConnectInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateTransitGatewayConnectInputBuilder {
    pub(crate) transport_transit_gateway_attachment_id: ::std::option::Option<::std::string::String>,
    pub(crate) options: ::std::option::Option<crate::types::CreateTransitGatewayConnectRequestOptions>,
    pub(crate) tag_specifications: ::std::option::Option<::std::vec::Vec<crate::types::TagSpecification>>,
    pub(crate) dry_run: ::std::option::Option<bool>,
}
impl CreateTransitGatewayConnectInputBuilder {
    /// <p>The ID of the transit gateway attachment. You can specify a VPC attachment or Amazon Web Services Direct Connect attachment.</p>
    /// This field is required.
    pub fn transport_transit_gateway_attachment_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.transport_transit_gateway_attachment_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the transit gateway attachment. You can specify a VPC attachment or Amazon Web Services Direct Connect attachment.</p>
    pub fn set_transport_transit_gateway_attachment_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.transport_transit_gateway_attachment_id = input;
        self
    }
    /// <p>The ID of the transit gateway attachment. You can specify a VPC attachment or Amazon Web Services Direct Connect attachment.</p>
    pub fn get_transport_transit_gateway_attachment_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.transport_transit_gateway_attachment_id
    }
    /// <p>The Connect attachment options.</p>
    /// This field is required.
    pub fn options(mut self, input: crate::types::CreateTransitGatewayConnectRequestOptions) -> Self {
        self.options = ::std::option::Option::Some(input);
        self
    }
    /// <p>The Connect attachment options.</p>
    pub fn set_options(mut self, input: ::std::option::Option<crate::types::CreateTransitGatewayConnectRequestOptions>) -> Self {
        self.options = input;
        self
    }
    /// <p>The Connect attachment options.</p>
    pub fn get_options(&self) -> &::std::option::Option<crate::types::CreateTransitGatewayConnectRequestOptions> {
        &self.options
    }
    /// Appends an item to `tag_specifications`.
    ///
    /// To override the contents of this collection use [`set_tag_specifications`](Self::set_tag_specifications).
    ///
    /// <p>The tags to apply to the Connect attachment.</p>
    pub fn tag_specifications(mut self, input: crate::types::TagSpecification) -> Self {
        let mut v = self.tag_specifications.unwrap_or_default();
        v.push(input);
        self.tag_specifications = ::std::option::Option::Some(v);
        self
    }
    /// <p>The tags to apply to the Connect attachment.</p>
    pub fn set_tag_specifications(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::TagSpecification>>) -> Self {
        self.tag_specifications = input;
        self
    }
    /// <p>The tags to apply to the Connect attachment.</p>
    pub fn get_tag_specifications(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::TagSpecification>> {
        &self.tag_specifications
    }
    /// <p>Checks whether you have the required permissions for the action, without actually making the request, and provides an error response. If you have the required permissions, the error response is <code>DryRunOperation</code>. Otherwise, it is <code>UnauthorizedOperation</code>.</p>
    pub fn dry_run(mut self, input: bool) -> Self {
        self.dry_run = ::std::option::Option::Some(input);
        self
    }
    /// <p>Checks whether you have the required permissions for the action, without actually making the request, and provides an error response. If you have the required permissions, the error response is <code>DryRunOperation</code>. Otherwise, it is <code>UnauthorizedOperation</code>.</p>
    pub fn set_dry_run(mut self, input: ::std::option::Option<bool>) -> Self {
        self.dry_run = input;
        self
    }
    /// <p>Checks whether you have the required permissions for the action, without actually making the request, and provides an error response. If you have the required permissions, the error response is <code>DryRunOperation</code>. Otherwise, it is <code>UnauthorizedOperation</code>.</p>
    pub fn get_dry_run(&self) -> &::std::option::Option<bool> {
        &self.dry_run
    }
    /// Consumes the builder and constructs a [`CreateTransitGatewayConnectInput`](crate::operation::create_transit_gateway_connect::CreateTransitGatewayConnectInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::create_transit_gateway_connect::CreateTransitGatewayConnectInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::create_transit_gateway_connect::CreateTransitGatewayConnectInput {
            transport_transit_gateway_attachment_id: self.transport_transit_gateway_attachment_id,
            options: self.options,
            tag_specifications: self.tag_specifications,
            dry_run: self.dry_run,
        })
    }
}
