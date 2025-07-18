// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateIpamResourceDiscoveryInput {
    /// <p>A check for whether you have the required permissions for the action without actually making the request and provides an error response. If you have the required permissions, the error response is <code>DryRunOperation</code>. Otherwise, it is <code>UnauthorizedOperation</code>.</p>
    pub dry_run: ::std::option::Option<bool>,
    /// <p>A description for the IPAM resource discovery.</p>
    pub description: ::std::option::Option<::std::string::String>,
    /// <p>Operating Regions for the IPAM resource discovery. Operating Regions are Amazon Web Services Regions where the IPAM is allowed to manage IP address CIDRs. IPAM only discovers and monitors resources in the Amazon Web Services Regions you select as operating Regions.</p>
    pub operating_regions: ::std::option::Option<::std::vec::Vec<crate::types::AddIpamOperatingRegion>>,
    /// <p>Tag specifications for the IPAM resource discovery.</p>
    pub tag_specifications: ::std::option::Option<::std::vec::Vec<crate::types::TagSpecification>>,
    /// <p>A client token for the IPAM resource discovery.</p>
    pub client_token: ::std::option::Option<::std::string::String>,
}
impl CreateIpamResourceDiscoveryInput {
    /// <p>A check for whether you have the required permissions for the action without actually making the request and provides an error response. If you have the required permissions, the error response is <code>DryRunOperation</code>. Otherwise, it is <code>UnauthorizedOperation</code>.</p>
    pub fn dry_run(&self) -> ::std::option::Option<bool> {
        self.dry_run
    }
    /// <p>A description for the IPAM resource discovery.</p>
    pub fn description(&self) -> ::std::option::Option<&str> {
        self.description.as_deref()
    }
    /// <p>Operating Regions for the IPAM resource discovery. Operating Regions are Amazon Web Services Regions where the IPAM is allowed to manage IP address CIDRs. IPAM only discovers and monitors resources in the Amazon Web Services Regions you select as operating Regions.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.operating_regions.is_none()`.
    pub fn operating_regions(&self) -> &[crate::types::AddIpamOperatingRegion] {
        self.operating_regions.as_deref().unwrap_or_default()
    }
    /// <p>Tag specifications for the IPAM resource discovery.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.tag_specifications.is_none()`.
    pub fn tag_specifications(&self) -> &[crate::types::TagSpecification] {
        self.tag_specifications.as_deref().unwrap_or_default()
    }
    /// <p>A client token for the IPAM resource discovery.</p>
    pub fn client_token(&self) -> ::std::option::Option<&str> {
        self.client_token.as_deref()
    }
}
impl CreateIpamResourceDiscoveryInput {
    /// Creates a new builder-style object to manufacture [`CreateIpamResourceDiscoveryInput`](crate::operation::create_ipam_resource_discovery::CreateIpamResourceDiscoveryInput).
    pub fn builder() -> crate::operation::create_ipam_resource_discovery::builders::CreateIpamResourceDiscoveryInputBuilder {
        crate::operation::create_ipam_resource_discovery::builders::CreateIpamResourceDiscoveryInputBuilder::default()
    }
}

/// A builder for [`CreateIpamResourceDiscoveryInput`](crate::operation::create_ipam_resource_discovery::CreateIpamResourceDiscoveryInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateIpamResourceDiscoveryInputBuilder {
    pub(crate) dry_run: ::std::option::Option<bool>,
    pub(crate) description: ::std::option::Option<::std::string::String>,
    pub(crate) operating_regions: ::std::option::Option<::std::vec::Vec<crate::types::AddIpamOperatingRegion>>,
    pub(crate) tag_specifications: ::std::option::Option<::std::vec::Vec<crate::types::TagSpecification>>,
    pub(crate) client_token: ::std::option::Option<::std::string::String>,
}
impl CreateIpamResourceDiscoveryInputBuilder {
    /// <p>A check for whether you have the required permissions for the action without actually making the request and provides an error response. If you have the required permissions, the error response is <code>DryRunOperation</code>. Otherwise, it is <code>UnauthorizedOperation</code>.</p>
    pub fn dry_run(mut self, input: bool) -> Self {
        self.dry_run = ::std::option::Option::Some(input);
        self
    }
    /// <p>A check for whether you have the required permissions for the action without actually making the request and provides an error response. If you have the required permissions, the error response is <code>DryRunOperation</code>. Otherwise, it is <code>UnauthorizedOperation</code>.</p>
    pub fn set_dry_run(mut self, input: ::std::option::Option<bool>) -> Self {
        self.dry_run = input;
        self
    }
    /// <p>A check for whether you have the required permissions for the action without actually making the request and provides an error response. If you have the required permissions, the error response is <code>DryRunOperation</code>. Otherwise, it is <code>UnauthorizedOperation</code>.</p>
    pub fn get_dry_run(&self) -> &::std::option::Option<bool> {
        &self.dry_run
    }
    /// <p>A description for the IPAM resource discovery.</p>
    pub fn description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A description for the IPAM resource discovery.</p>
    pub fn set_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.description = input;
        self
    }
    /// <p>A description for the IPAM resource discovery.</p>
    pub fn get_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.description
    }
    /// Appends an item to `operating_regions`.
    ///
    /// To override the contents of this collection use [`set_operating_regions`](Self::set_operating_regions).
    ///
    /// <p>Operating Regions for the IPAM resource discovery. Operating Regions are Amazon Web Services Regions where the IPAM is allowed to manage IP address CIDRs. IPAM only discovers and monitors resources in the Amazon Web Services Regions you select as operating Regions.</p>
    pub fn operating_regions(mut self, input: crate::types::AddIpamOperatingRegion) -> Self {
        let mut v = self.operating_regions.unwrap_or_default();
        v.push(input);
        self.operating_regions = ::std::option::Option::Some(v);
        self
    }
    /// <p>Operating Regions for the IPAM resource discovery. Operating Regions are Amazon Web Services Regions where the IPAM is allowed to manage IP address CIDRs. IPAM only discovers and monitors resources in the Amazon Web Services Regions you select as operating Regions.</p>
    pub fn set_operating_regions(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::AddIpamOperatingRegion>>) -> Self {
        self.operating_regions = input;
        self
    }
    /// <p>Operating Regions for the IPAM resource discovery. Operating Regions are Amazon Web Services Regions where the IPAM is allowed to manage IP address CIDRs. IPAM only discovers and monitors resources in the Amazon Web Services Regions you select as operating Regions.</p>
    pub fn get_operating_regions(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::AddIpamOperatingRegion>> {
        &self.operating_regions
    }
    /// Appends an item to `tag_specifications`.
    ///
    /// To override the contents of this collection use [`set_tag_specifications`](Self::set_tag_specifications).
    ///
    /// <p>Tag specifications for the IPAM resource discovery.</p>
    pub fn tag_specifications(mut self, input: crate::types::TagSpecification) -> Self {
        let mut v = self.tag_specifications.unwrap_or_default();
        v.push(input);
        self.tag_specifications = ::std::option::Option::Some(v);
        self
    }
    /// <p>Tag specifications for the IPAM resource discovery.</p>
    pub fn set_tag_specifications(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::TagSpecification>>) -> Self {
        self.tag_specifications = input;
        self
    }
    /// <p>Tag specifications for the IPAM resource discovery.</p>
    pub fn get_tag_specifications(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::TagSpecification>> {
        &self.tag_specifications
    }
    /// <p>A client token for the IPAM resource discovery.</p>
    pub fn client_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.client_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A client token for the IPAM resource discovery.</p>
    pub fn set_client_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.client_token = input;
        self
    }
    /// <p>A client token for the IPAM resource discovery.</p>
    pub fn get_client_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.client_token
    }
    /// Consumes the builder and constructs a [`CreateIpamResourceDiscoveryInput`](crate::operation::create_ipam_resource_discovery::CreateIpamResourceDiscoveryInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::create_ipam_resource_discovery::CreateIpamResourceDiscoveryInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::create_ipam_resource_discovery::CreateIpamResourceDiscoveryInput {
            dry_run: self.dry_run,
            description: self.description,
            operating_regions: self.operating_regions,
            tag_specifications: self.tag_specifications,
            client_token: self.client_token,
        })
    }
}
