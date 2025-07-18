// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The configuration settings for in-bound network access to your workspace.</p>
/// <p>When this is configured, only listed IP addresses and VPC endpoints will be able to access your workspace. Standard Grafana authentication and authorization are still required.</p>
/// <p>Access is granted to a caller that is in either the IP address list or the VPC endpoint list - they do not need to be in both.</p>
/// <p>If this is not configured, or is removed, then all IP addresses and VPC endpoints are allowed. Standard Grafana authentication and authorization are still required.</p><note>
/// <p>While both <code>prefixListIds</code> and <code>vpceIds</code> are required, you can pass in an empty array of strings for either parameter if you do not want to allow any of that type.</p>
/// <p>If both are passed as empty arrays, no traffic is allowed to the workspace, because only <i>explicitly</i> allowed connections are accepted.</p>
/// </note>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct NetworkAccessConfiguration {
    /// <p>An array of prefix list IDs. A prefix list is a list of CIDR ranges of IP addresses. The IP addresses specified are allowed to access your workspace. If the list is not included in the configuration (passed an empty array) then no IP addresses are allowed to access the workspace. You create a prefix list using the Amazon VPC console.</p>
    /// <p>Prefix list IDs have the format <code>pl-<i>1a2b3c4d</i> </code>.</p>
    /// <p>For more information about prefix lists, see <a href="https://docs.aws.amazon.com/vpc/latest/userguide/managed-prefix-lists.html">Group CIDR blocks using managed prefix lists</a>in the <i>Amazon Virtual Private Cloud User Guide</i>.</p>
    pub prefix_list_ids: ::std::vec::Vec<::std::string::String>,
    /// <p>An array of Amazon VPC endpoint IDs for the workspace. You can create VPC endpoints to your Amazon Managed Grafana workspace for access from within a VPC. If a <code>NetworkAccessConfiguration</code> is specified then only VPC endpoints specified here are allowed to access the workspace. If you pass in an empty array of strings, then no VPCs are allowed to access the workspace.</p>
    /// <p>VPC endpoint IDs have the format <code>vpce-<i>1a2b3c4d</i> </code>.</p>
    /// <p>For more information about creating an interface VPC endpoint, see <a href="https://docs.aws.amazon.com/grafana/latest/userguide/VPC-endpoints">Interface VPC endpoints</a> in the <i>Amazon Managed Grafana User Guide</i>.</p><note>
    /// <p>The only VPC endpoints that can be specified here are interface VPC endpoints for Grafana workspaces (using the <code>com.amazonaws.\[region\].grafana-workspace</code> service endpoint). Other VPC endpoints are ignored.</p>
    /// </note>
    pub vpce_ids: ::std::vec::Vec<::std::string::String>,
}
impl NetworkAccessConfiguration {
    /// <p>An array of prefix list IDs. A prefix list is a list of CIDR ranges of IP addresses. The IP addresses specified are allowed to access your workspace. If the list is not included in the configuration (passed an empty array) then no IP addresses are allowed to access the workspace. You create a prefix list using the Amazon VPC console.</p>
    /// <p>Prefix list IDs have the format <code>pl-<i>1a2b3c4d</i> </code>.</p>
    /// <p>For more information about prefix lists, see <a href="https://docs.aws.amazon.com/vpc/latest/userguide/managed-prefix-lists.html">Group CIDR blocks using managed prefix lists</a>in the <i>Amazon Virtual Private Cloud User Guide</i>.</p>
    pub fn prefix_list_ids(&self) -> &[::std::string::String] {
        use std::ops::Deref;
        self.prefix_list_ids.deref()
    }
    /// <p>An array of Amazon VPC endpoint IDs for the workspace. You can create VPC endpoints to your Amazon Managed Grafana workspace for access from within a VPC. If a <code>NetworkAccessConfiguration</code> is specified then only VPC endpoints specified here are allowed to access the workspace. If you pass in an empty array of strings, then no VPCs are allowed to access the workspace.</p>
    /// <p>VPC endpoint IDs have the format <code>vpce-<i>1a2b3c4d</i> </code>.</p>
    /// <p>For more information about creating an interface VPC endpoint, see <a href="https://docs.aws.amazon.com/grafana/latest/userguide/VPC-endpoints">Interface VPC endpoints</a> in the <i>Amazon Managed Grafana User Guide</i>.</p><note>
    /// <p>The only VPC endpoints that can be specified here are interface VPC endpoints for Grafana workspaces (using the <code>com.amazonaws.\[region\].grafana-workspace</code> service endpoint). Other VPC endpoints are ignored.</p>
    /// </note>
    pub fn vpce_ids(&self) -> &[::std::string::String] {
        use std::ops::Deref;
        self.vpce_ids.deref()
    }
}
impl NetworkAccessConfiguration {
    /// Creates a new builder-style object to manufacture [`NetworkAccessConfiguration`](crate::types::NetworkAccessConfiguration).
    pub fn builder() -> crate::types::builders::NetworkAccessConfigurationBuilder {
        crate::types::builders::NetworkAccessConfigurationBuilder::default()
    }
}

/// A builder for [`NetworkAccessConfiguration`](crate::types::NetworkAccessConfiguration).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct NetworkAccessConfigurationBuilder {
    pub(crate) prefix_list_ids: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) vpce_ids: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl NetworkAccessConfigurationBuilder {
    /// Appends an item to `prefix_list_ids`.
    ///
    /// To override the contents of this collection use [`set_prefix_list_ids`](Self::set_prefix_list_ids).
    ///
    /// <p>An array of prefix list IDs. A prefix list is a list of CIDR ranges of IP addresses. The IP addresses specified are allowed to access your workspace. If the list is not included in the configuration (passed an empty array) then no IP addresses are allowed to access the workspace. You create a prefix list using the Amazon VPC console.</p>
    /// <p>Prefix list IDs have the format <code>pl-<i>1a2b3c4d</i> </code>.</p>
    /// <p>For more information about prefix lists, see <a href="https://docs.aws.amazon.com/vpc/latest/userguide/managed-prefix-lists.html">Group CIDR blocks using managed prefix lists</a>in the <i>Amazon Virtual Private Cloud User Guide</i>.</p>
    pub fn prefix_list_ids(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.prefix_list_ids.unwrap_or_default();
        v.push(input.into());
        self.prefix_list_ids = ::std::option::Option::Some(v);
        self
    }
    /// <p>An array of prefix list IDs. A prefix list is a list of CIDR ranges of IP addresses. The IP addresses specified are allowed to access your workspace. If the list is not included in the configuration (passed an empty array) then no IP addresses are allowed to access the workspace. You create a prefix list using the Amazon VPC console.</p>
    /// <p>Prefix list IDs have the format <code>pl-<i>1a2b3c4d</i> </code>.</p>
    /// <p>For more information about prefix lists, see <a href="https://docs.aws.amazon.com/vpc/latest/userguide/managed-prefix-lists.html">Group CIDR blocks using managed prefix lists</a>in the <i>Amazon Virtual Private Cloud User Guide</i>.</p>
    pub fn set_prefix_list_ids(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.prefix_list_ids = input;
        self
    }
    /// <p>An array of prefix list IDs. A prefix list is a list of CIDR ranges of IP addresses. The IP addresses specified are allowed to access your workspace. If the list is not included in the configuration (passed an empty array) then no IP addresses are allowed to access the workspace. You create a prefix list using the Amazon VPC console.</p>
    /// <p>Prefix list IDs have the format <code>pl-<i>1a2b3c4d</i> </code>.</p>
    /// <p>For more information about prefix lists, see <a href="https://docs.aws.amazon.com/vpc/latest/userguide/managed-prefix-lists.html">Group CIDR blocks using managed prefix lists</a>in the <i>Amazon Virtual Private Cloud User Guide</i>.</p>
    pub fn get_prefix_list_ids(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.prefix_list_ids
    }
    /// Appends an item to `vpce_ids`.
    ///
    /// To override the contents of this collection use [`set_vpce_ids`](Self::set_vpce_ids).
    ///
    /// <p>An array of Amazon VPC endpoint IDs for the workspace. You can create VPC endpoints to your Amazon Managed Grafana workspace for access from within a VPC. If a <code>NetworkAccessConfiguration</code> is specified then only VPC endpoints specified here are allowed to access the workspace. If you pass in an empty array of strings, then no VPCs are allowed to access the workspace.</p>
    /// <p>VPC endpoint IDs have the format <code>vpce-<i>1a2b3c4d</i> </code>.</p>
    /// <p>For more information about creating an interface VPC endpoint, see <a href="https://docs.aws.amazon.com/grafana/latest/userguide/VPC-endpoints">Interface VPC endpoints</a> in the <i>Amazon Managed Grafana User Guide</i>.</p><note>
    /// <p>The only VPC endpoints that can be specified here are interface VPC endpoints for Grafana workspaces (using the <code>com.amazonaws.\[region\].grafana-workspace</code> service endpoint). Other VPC endpoints are ignored.</p>
    /// </note>
    pub fn vpce_ids(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.vpce_ids.unwrap_or_default();
        v.push(input.into());
        self.vpce_ids = ::std::option::Option::Some(v);
        self
    }
    /// <p>An array of Amazon VPC endpoint IDs for the workspace. You can create VPC endpoints to your Amazon Managed Grafana workspace for access from within a VPC. If a <code>NetworkAccessConfiguration</code> is specified then only VPC endpoints specified here are allowed to access the workspace. If you pass in an empty array of strings, then no VPCs are allowed to access the workspace.</p>
    /// <p>VPC endpoint IDs have the format <code>vpce-<i>1a2b3c4d</i> </code>.</p>
    /// <p>For more information about creating an interface VPC endpoint, see <a href="https://docs.aws.amazon.com/grafana/latest/userguide/VPC-endpoints">Interface VPC endpoints</a> in the <i>Amazon Managed Grafana User Guide</i>.</p><note>
    /// <p>The only VPC endpoints that can be specified here are interface VPC endpoints for Grafana workspaces (using the <code>com.amazonaws.\[region\].grafana-workspace</code> service endpoint). Other VPC endpoints are ignored.</p>
    /// </note>
    pub fn set_vpce_ids(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.vpce_ids = input;
        self
    }
    /// <p>An array of Amazon VPC endpoint IDs for the workspace. You can create VPC endpoints to your Amazon Managed Grafana workspace for access from within a VPC. If a <code>NetworkAccessConfiguration</code> is specified then only VPC endpoints specified here are allowed to access the workspace. If you pass in an empty array of strings, then no VPCs are allowed to access the workspace.</p>
    /// <p>VPC endpoint IDs have the format <code>vpce-<i>1a2b3c4d</i> </code>.</p>
    /// <p>For more information about creating an interface VPC endpoint, see <a href="https://docs.aws.amazon.com/grafana/latest/userguide/VPC-endpoints">Interface VPC endpoints</a> in the <i>Amazon Managed Grafana User Guide</i>.</p><note>
    /// <p>The only VPC endpoints that can be specified here are interface VPC endpoints for Grafana workspaces (using the <code>com.amazonaws.\[region\].grafana-workspace</code> service endpoint). Other VPC endpoints are ignored.</p>
    /// </note>
    pub fn get_vpce_ids(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.vpce_ids
    }
    /// Consumes the builder and constructs a [`NetworkAccessConfiguration`](crate::types::NetworkAccessConfiguration).
    /// This method will fail if any of the following fields are not set:
    /// - [`prefix_list_ids`](crate::types::builders::NetworkAccessConfigurationBuilder::prefix_list_ids)
    /// - [`vpce_ids`](crate::types::builders::NetworkAccessConfigurationBuilder::vpce_ids)
    pub fn build(self) -> ::std::result::Result<crate::types::NetworkAccessConfiguration, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::NetworkAccessConfiguration {
            prefix_list_ids: self.prefix_list_ids.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "prefix_list_ids",
                    "prefix_list_ids was not specified but it is required when building NetworkAccessConfiguration",
                )
            })?,
            vpce_ids: self.vpce_ids.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "vpce_ids",
                    "vpce_ids was not specified but it is required when building NetworkAccessConfiguration",
                )
            })?,
        })
    }
}
