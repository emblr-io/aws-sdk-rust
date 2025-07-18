// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetIpamResourceCidrsInput {
    /// <p>A check for whether you have the required permissions for the action without actually making the request and provides an error response. If you have the required permissions, the error response is <code>DryRunOperation</code>. Otherwise, it is <code>UnauthorizedOperation</code>.</p>
    pub dry_run: ::std::option::Option<bool>,
    /// <p>One or more filters for the request. For more information about filtering, see <a href="https://docs.aws.amazon.com/cli/latest/userguide/cli-usage-filter.html">Filtering CLI output</a>.</p>
    pub filters: ::std::option::Option<::std::vec::Vec<crate::types::Filter>>,
    /// <p>The maximum number of results to return in the request.</p>
    pub max_results: ::std::option::Option<i32>,
    /// <p>The token for the next page of results.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    /// <p>The ID of the scope that the resource is in.</p>
    pub ipam_scope_id: ::std::option::Option<::std::string::String>,
    /// <p>The ID of the IPAM pool that the resource is in.</p>
    pub ipam_pool_id: ::std::option::Option<::std::string::String>,
    /// <p>The ID of the resource.</p>
    pub resource_id: ::std::option::Option<::std::string::String>,
    /// <p>The resource type.</p>
    pub resource_type: ::std::option::Option<crate::types::IpamResourceType>,
    /// <p>The resource tag.</p>
    pub resource_tag: ::std::option::Option<crate::types::RequestIpamResourceTag>,
    /// <p>The ID of the Amazon Web Services account that owns the resource.</p>
    pub resource_owner: ::std::option::Option<::std::string::String>,
}
impl GetIpamResourceCidrsInput {
    /// <p>A check for whether you have the required permissions for the action without actually making the request and provides an error response. If you have the required permissions, the error response is <code>DryRunOperation</code>. Otherwise, it is <code>UnauthorizedOperation</code>.</p>
    pub fn dry_run(&self) -> ::std::option::Option<bool> {
        self.dry_run
    }
    /// <p>One or more filters for the request. For more information about filtering, see <a href="https://docs.aws.amazon.com/cli/latest/userguide/cli-usage-filter.html">Filtering CLI output</a>.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.filters.is_none()`.
    pub fn filters(&self) -> &[crate::types::Filter] {
        self.filters.as_deref().unwrap_or_default()
    }
    /// <p>The maximum number of results to return in the request.</p>
    pub fn max_results(&self) -> ::std::option::Option<i32> {
        self.max_results
    }
    /// <p>The token for the next page of results.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
    /// <p>The ID of the scope that the resource is in.</p>
    pub fn ipam_scope_id(&self) -> ::std::option::Option<&str> {
        self.ipam_scope_id.as_deref()
    }
    /// <p>The ID of the IPAM pool that the resource is in.</p>
    pub fn ipam_pool_id(&self) -> ::std::option::Option<&str> {
        self.ipam_pool_id.as_deref()
    }
    /// <p>The ID of the resource.</p>
    pub fn resource_id(&self) -> ::std::option::Option<&str> {
        self.resource_id.as_deref()
    }
    /// <p>The resource type.</p>
    pub fn resource_type(&self) -> ::std::option::Option<&crate::types::IpamResourceType> {
        self.resource_type.as_ref()
    }
    /// <p>The resource tag.</p>
    pub fn resource_tag(&self) -> ::std::option::Option<&crate::types::RequestIpamResourceTag> {
        self.resource_tag.as_ref()
    }
    /// <p>The ID of the Amazon Web Services account that owns the resource.</p>
    pub fn resource_owner(&self) -> ::std::option::Option<&str> {
        self.resource_owner.as_deref()
    }
}
impl GetIpamResourceCidrsInput {
    /// Creates a new builder-style object to manufacture [`GetIpamResourceCidrsInput`](crate::operation::get_ipam_resource_cidrs::GetIpamResourceCidrsInput).
    pub fn builder() -> crate::operation::get_ipam_resource_cidrs::builders::GetIpamResourceCidrsInputBuilder {
        crate::operation::get_ipam_resource_cidrs::builders::GetIpamResourceCidrsInputBuilder::default()
    }
}

/// A builder for [`GetIpamResourceCidrsInput`](crate::operation::get_ipam_resource_cidrs::GetIpamResourceCidrsInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetIpamResourceCidrsInputBuilder {
    pub(crate) dry_run: ::std::option::Option<bool>,
    pub(crate) filters: ::std::option::Option<::std::vec::Vec<crate::types::Filter>>,
    pub(crate) max_results: ::std::option::Option<i32>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    pub(crate) ipam_scope_id: ::std::option::Option<::std::string::String>,
    pub(crate) ipam_pool_id: ::std::option::Option<::std::string::String>,
    pub(crate) resource_id: ::std::option::Option<::std::string::String>,
    pub(crate) resource_type: ::std::option::Option<crate::types::IpamResourceType>,
    pub(crate) resource_tag: ::std::option::Option<crate::types::RequestIpamResourceTag>,
    pub(crate) resource_owner: ::std::option::Option<::std::string::String>,
}
impl GetIpamResourceCidrsInputBuilder {
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
    /// Appends an item to `filters`.
    ///
    /// To override the contents of this collection use [`set_filters`](Self::set_filters).
    ///
    /// <p>One or more filters for the request. For more information about filtering, see <a href="https://docs.aws.amazon.com/cli/latest/userguide/cli-usage-filter.html">Filtering CLI output</a>.</p>
    pub fn filters(mut self, input: crate::types::Filter) -> Self {
        let mut v = self.filters.unwrap_or_default();
        v.push(input);
        self.filters = ::std::option::Option::Some(v);
        self
    }
    /// <p>One or more filters for the request. For more information about filtering, see <a href="https://docs.aws.amazon.com/cli/latest/userguide/cli-usage-filter.html">Filtering CLI output</a>.</p>
    pub fn set_filters(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Filter>>) -> Self {
        self.filters = input;
        self
    }
    /// <p>One or more filters for the request. For more information about filtering, see <a href="https://docs.aws.amazon.com/cli/latest/userguide/cli-usage-filter.html">Filtering CLI output</a>.</p>
    pub fn get_filters(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Filter>> {
        &self.filters
    }
    /// <p>The maximum number of results to return in the request.</p>
    pub fn max_results(mut self, input: i32) -> Self {
        self.max_results = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum number of results to return in the request.</p>
    pub fn set_max_results(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_results = input;
        self
    }
    /// <p>The maximum number of results to return in the request.</p>
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
    /// <p>The ID of the scope that the resource is in.</p>
    /// This field is required.
    pub fn ipam_scope_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.ipam_scope_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the scope that the resource is in.</p>
    pub fn set_ipam_scope_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.ipam_scope_id = input;
        self
    }
    /// <p>The ID of the scope that the resource is in.</p>
    pub fn get_ipam_scope_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.ipam_scope_id
    }
    /// <p>The ID of the IPAM pool that the resource is in.</p>
    pub fn ipam_pool_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.ipam_pool_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the IPAM pool that the resource is in.</p>
    pub fn set_ipam_pool_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.ipam_pool_id = input;
        self
    }
    /// <p>The ID of the IPAM pool that the resource is in.</p>
    pub fn get_ipam_pool_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.ipam_pool_id
    }
    /// <p>The ID of the resource.</p>
    pub fn resource_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.resource_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the resource.</p>
    pub fn set_resource_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.resource_id = input;
        self
    }
    /// <p>The ID of the resource.</p>
    pub fn get_resource_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.resource_id
    }
    /// <p>The resource type.</p>
    pub fn resource_type(mut self, input: crate::types::IpamResourceType) -> Self {
        self.resource_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The resource type.</p>
    pub fn set_resource_type(mut self, input: ::std::option::Option<crate::types::IpamResourceType>) -> Self {
        self.resource_type = input;
        self
    }
    /// <p>The resource type.</p>
    pub fn get_resource_type(&self) -> &::std::option::Option<crate::types::IpamResourceType> {
        &self.resource_type
    }
    /// <p>The resource tag.</p>
    pub fn resource_tag(mut self, input: crate::types::RequestIpamResourceTag) -> Self {
        self.resource_tag = ::std::option::Option::Some(input);
        self
    }
    /// <p>The resource tag.</p>
    pub fn set_resource_tag(mut self, input: ::std::option::Option<crate::types::RequestIpamResourceTag>) -> Self {
        self.resource_tag = input;
        self
    }
    /// <p>The resource tag.</p>
    pub fn get_resource_tag(&self) -> &::std::option::Option<crate::types::RequestIpamResourceTag> {
        &self.resource_tag
    }
    /// <p>The ID of the Amazon Web Services account that owns the resource.</p>
    pub fn resource_owner(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.resource_owner = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the Amazon Web Services account that owns the resource.</p>
    pub fn set_resource_owner(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.resource_owner = input;
        self
    }
    /// <p>The ID of the Amazon Web Services account that owns the resource.</p>
    pub fn get_resource_owner(&self) -> &::std::option::Option<::std::string::String> {
        &self.resource_owner
    }
    /// Consumes the builder and constructs a [`GetIpamResourceCidrsInput`](crate::operation::get_ipam_resource_cidrs::GetIpamResourceCidrsInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::get_ipam_resource_cidrs::GetIpamResourceCidrsInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::get_ipam_resource_cidrs::GetIpamResourceCidrsInput {
            dry_run: self.dry_run,
            filters: self.filters,
            max_results: self.max_results,
            next_token: self.next_token,
            ipam_scope_id: self.ipam_scope_id,
            ipam_pool_id: self.ipam_pool_id,
            resource_id: self.resource_id,
            resource_type: self.resource_type,
            resource_tag: self.resource_tag,
            resource_owner: self.resource_owner,
        })
    }
}
