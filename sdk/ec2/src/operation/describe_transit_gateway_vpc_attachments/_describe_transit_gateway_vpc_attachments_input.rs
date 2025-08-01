// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeTransitGatewayVpcAttachmentsInput {
    /// <p>The IDs of the attachments.</p>
    pub transit_gateway_attachment_ids: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>One or more filters. The possible values are:</p>
    /// <ul>
    /// <li>
    /// <p><code>state</code> - The state of the attachment. Valid values are <code>available</code> | <code>deleted</code> | <code>deleting</code> | <code>failed</code> | <code>failing</code> | <code>initiatingRequest</code> | <code>modifying</code> | <code>pendingAcceptance</code> | <code>pending</code> | <code>rollingBack</code> | <code>rejected</code> | <code>rejecting</code>.</p></li>
    /// <li>
    /// <p><code>transit-gateway-attachment-id</code> - The ID of the attachment.</p></li>
    /// <li>
    /// <p><code>transit-gateway-id</code> - The ID of the transit gateway.</p></li>
    /// <li>
    /// <p><code>vpc-id</code> - The ID of the VPC.</p></li>
    /// </ul>
    pub filters: ::std::option::Option<::std::vec::Vec<crate::types::Filter>>,
    /// <p>The maximum number of results to return with a single call. To retrieve the remaining results, make another call with the returned <code>nextToken</code> value.</p>
    pub max_results: ::std::option::Option<i32>,
    /// <p>The token for the next page of results.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    /// <p>Checks whether you have the required permissions for the action, without actually making the request, and provides an error response. If you have the required permissions, the error response is <code>DryRunOperation</code>. Otherwise, it is <code>UnauthorizedOperation</code>.</p>
    pub dry_run: ::std::option::Option<bool>,
}
impl DescribeTransitGatewayVpcAttachmentsInput {
    /// <p>The IDs of the attachments.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.transit_gateway_attachment_ids.is_none()`.
    pub fn transit_gateway_attachment_ids(&self) -> &[::std::string::String] {
        self.transit_gateway_attachment_ids.as_deref().unwrap_or_default()
    }
    /// <p>One or more filters. The possible values are:</p>
    /// <ul>
    /// <li>
    /// <p><code>state</code> - The state of the attachment. Valid values are <code>available</code> | <code>deleted</code> | <code>deleting</code> | <code>failed</code> | <code>failing</code> | <code>initiatingRequest</code> | <code>modifying</code> | <code>pendingAcceptance</code> | <code>pending</code> | <code>rollingBack</code> | <code>rejected</code> | <code>rejecting</code>.</p></li>
    /// <li>
    /// <p><code>transit-gateway-attachment-id</code> - The ID of the attachment.</p></li>
    /// <li>
    /// <p><code>transit-gateway-id</code> - The ID of the transit gateway.</p></li>
    /// <li>
    /// <p><code>vpc-id</code> - The ID of the VPC.</p></li>
    /// </ul>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.filters.is_none()`.
    pub fn filters(&self) -> &[crate::types::Filter] {
        self.filters.as_deref().unwrap_or_default()
    }
    /// <p>The maximum number of results to return with a single call. To retrieve the remaining results, make another call with the returned <code>nextToken</code> value.</p>
    pub fn max_results(&self) -> ::std::option::Option<i32> {
        self.max_results
    }
    /// <p>The token for the next page of results.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
    /// <p>Checks whether you have the required permissions for the action, without actually making the request, and provides an error response. If you have the required permissions, the error response is <code>DryRunOperation</code>. Otherwise, it is <code>UnauthorizedOperation</code>.</p>
    pub fn dry_run(&self) -> ::std::option::Option<bool> {
        self.dry_run
    }
}
impl DescribeTransitGatewayVpcAttachmentsInput {
    /// Creates a new builder-style object to manufacture [`DescribeTransitGatewayVpcAttachmentsInput`](crate::operation::describe_transit_gateway_vpc_attachments::DescribeTransitGatewayVpcAttachmentsInput).
    pub fn builder() -> crate::operation::describe_transit_gateway_vpc_attachments::builders::DescribeTransitGatewayVpcAttachmentsInputBuilder {
        crate::operation::describe_transit_gateway_vpc_attachments::builders::DescribeTransitGatewayVpcAttachmentsInputBuilder::default()
    }
}

/// A builder for [`DescribeTransitGatewayVpcAttachmentsInput`](crate::operation::describe_transit_gateway_vpc_attachments::DescribeTransitGatewayVpcAttachmentsInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeTransitGatewayVpcAttachmentsInputBuilder {
    pub(crate) transit_gateway_attachment_ids: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) filters: ::std::option::Option<::std::vec::Vec<crate::types::Filter>>,
    pub(crate) max_results: ::std::option::Option<i32>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    pub(crate) dry_run: ::std::option::Option<bool>,
}
impl DescribeTransitGatewayVpcAttachmentsInputBuilder {
    /// Appends an item to `transit_gateway_attachment_ids`.
    ///
    /// To override the contents of this collection use [`set_transit_gateway_attachment_ids`](Self::set_transit_gateway_attachment_ids).
    ///
    /// <p>The IDs of the attachments.</p>
    pub fn transit_gateway_attachment_ids(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.transit_gateway_attachment_ids.unwrap_or_default();
        v.push(input.into());
        self.transit_gateway_attachment_ids = ::std::option::Option::Some(v);
        self
    }
    /// <p>The IDs of the attachments.</p>
    pub fn set_transit_gateway_attachment_ids(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.transit_gateway_attachment_ids = input;
        self
    }
    /// <p>The IDs of the attachments.</p>
    pub fn get_transit_gateway_attachment_ids(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.transit_gateway_attachment_ids
    }
    /// Appends an item to `filters`.
    ///
    /// To override the contents of this collection use [`set_filters`](Self::set_filters).
    ///
    /// <p>One or more filters. The possible values are:</p>
    /// <ul>
    /// <li>
    /// <p><code>state</code> - The state of the attachment. Valid values are <code>available</code> | <code>deleted</code> | <code>deleting</code> | <code>failed</code> | <code>failing</code> | <code>initiatingRequest</code> | <code>modifying</code> | <code>pendingAcceptance</code> | <code>pending</code> | <code>rollingBack</code> | <code>rejected</code> | <code>rejecting</code>.</p></li>
    /// <li>
    /// <p><code>transit-gateway-attachment-id</code> - The ID of the attachment.</p></li>
    /// <li>
    /// <p><code>transit-gateway-id</code> - The ID of the transit gateway.</p></li>
    /// <li>
    /// <p><code>vpc-id</code> - The ID of the VPC.</p></li>
    /// </ul>
    pub fn filters(mut self, input: crate::types::Filter) -> Self {
        let mut v = self.filters.unwrap_or_default();
        v.push(input);
        self.filters = ::std::option::Option::Some(v);
        self
    }
    /// <p>One or more filters. The possible values are:</p>
    /// <ul>
    /// <li>
    /// <p><code>state</code> - The state of the attachment. Valid values are <code>available</code> | <code>deleted</code> | <code>deleting</code> | <code>failed</code> | <code>failing</code> | <code>initiatingRequest</code> | <code>modifying</code> | <code>pendingAcceptance</code> | <code>pending</code> | <code>rollingBack</code> | <code>rejected</code> | <code>rejecting</code>.</p></li>
    /// <li>
    /// <p><code>transit-gateway-attachment-id</code> - The ID of the attachment.</p></li>
    /// <li>
    /// <p><code>transit-gateway-id</code> - The ID of the transit gateway.</p></li>
    /// <li>
    /// <p><code>vpc-id</code> - The ID of the VPC.</p></li>
    /// </ul>
    pub fn set_filters(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Filter>>) -> Self {
        self.filters = input;
        self
    }
    /// <p>One or more filters. The possible values are:</p>
    /// <ul>
    /// <li>
    /// <p><code>state</code> - The state of the attachment. Valid values are <code>available</code> | <code>deleted</code> | <code>deleting</code> | <code>failed</code> | <code>failing</code> | <code>initiatingRequest</code> | <code>modifying</code> | <code>pendingAcceptance</code> | <code>pending</code> | <code>rollingBack</code> | <code>rejected</code> | <code>rejecting</code>.</p></li>
    /// <li>
    /// <p><code>transit-gateway-attachment-id</code> - The ID of the attachment.</p></li>
    /// <li>
    /// <p><code>transit-gateway-id</code> - The ID of the transit gateway.</p></li>
    /// <li>
    /// <p><code>vpc-id</code> - The ID of the VPC.</p></li>
    /// </ul>
    pub fn get_filters(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Filter>> {
        &self.filters
    }
    /// <p>The maximum number of results to return with a single call. To retrieve the remaining results, make another call with the returned <code>nextToken</code> value.</p>
    pub fn max_results(mut self, input: i32) -> Self {
        self.max_results = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum number of results to return with a single call. To retrieve the remaining results, make another call with the returned <code>nextToken</code> value.</p>
    pub fn set_max_results(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_results = input;
        self
    }
    /// <p>The maximum number of results to return with a single call. To retrieve the remaining results, make another call with the returned <code>nextToken</code> value.</p>
    pub fn get_max_results(&self) -> &::std::option::Option<i32> {
        &self.max_results
    }
    /// <p>The token for the next page of results.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The token for the next page of results.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>The token for the next page of results.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
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
    /// Consumes the builder and constructs a [`DescribeTransitGatewayVpcAttachmentsInput`](crate::operation::describe_transit_gateway_vpc_attachments::DescribeTransitGatewayVpcAttachmentsInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::describe_transit_gateway_vpc_attachments::DescribeTransitGatewayVpcAttachmentsInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(
            crate::operation::describe_transit_gateway_vpc_attachments::DescribeTransitGatewayVpcAttachmentsInput {
                transit_gateway_attachment_ids: self.transit_gateway_attachment_ids,
                filters: self.filters,
                max_results: self.max_results,
                next_token: self.next_token,
                dry_run: self.dry_run,
            },
        )
    }
}
