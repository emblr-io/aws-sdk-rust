// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ModifyInstanceMetadataOptionsInput {
    /// <p>The ID of the instance.</p>
    pub instance_id: ::std::option::Option<::std::string::String>,
    /// <p>Indicates whether IMDSv2 is required.</p>
    /// <ul>
    /// <li>
    /// <p><code>optional</code> - IMDSv2 is optional. You can choose whether to send a session token in your instance metadata retrieval requests. If you retrieve IAM role credentials without a session token, you receive the IMDSv1 role credentials. If you retrieve IAM role credentials using a valid session token, you receive the IMDSv2 role credentials.</p></li>
    /// <li>
    /// <p><code>required</code> - IMDSv2 is required. You must send a session token in your instance metadata retrieval requests. With this option, retrieving the IAM role credentials always returns IMDSv2 credentials; IMDSv1 credentials are not available.</p></li>
    /// </ul>
    /// <p>Default:</p>
    /// <ul>
    /// <li>
    /// <p>If the value of <code>ImdsSupport</code> for the Amazon Machine Image (AMI) for your instance is <code>v2.0</code> and the account level default is set to <code>no-preference</code>, the default is <code>required</code>.</p></li>
    /// <li>
    /// <p>If the value of <code>ImdsSupport</code> for the Amazon Machine Image (AMI) for your instance is <code>v2.0</code>, but the account level default is set to <code>V1 or V2</code>, the default is <code>optional</code>.</p></li>
    /// </ul>
    /// <p>The default value can also be affected by other combinations of parameters. For more information, see <a href="https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-options.html#instance-metadata-options-order-of-precedence">Order of precedence for instance metadata options</a> in the <i>Amazon EC2 User Guide</i>.</p>
    pub http_tokens: ::std::option::Option<crate::types::HttpTokensState>,
    /// <p>The desired HTTP PUT response hop limit for instance metadata requests. The larger the number, the further instance metadata requests can travel. If no parameter is specified, the existing state is maintained.</p>
    /// <p>Possible values: Integers from 1 to 64</p>
    pub http_put_response_hop_limit: ::std::option::Option<i32>,
    /// <p>Enables or disables the HTTP metadata endpoint on your instances. If this parameter is not specified, the existing state is maintained.</p>
    /// <p>If you specify a value of <code>disabled</code>, you cannot access your instance metadata.</p>
    pub http_endpoint: ::std::option::Option<crate::types::InstanceMetadataEndpointState>,
    /// <p>Checks whether you have the required permissions for the action, without actually making the request, and provides an error response. If you have the required permissions, the error response is <code>DryRunOperation</code>. Otherwise, it is <code>UnauthorizedOperation</code>.</p>
    pub dry_run: ::std::option::Option<bool>,
    /// <p>Enables or disables the IPv6 endpoint for the instance metadata service. Applies only if you enabled the HTTP metadata endpoint.</p>
    pub http_protocol_ipv6: ::std::option::Option<crate::types::InstanceMetadataProtocolState>,
    /// <p>Set to <code>enabled</code> to allow access to instance tags from the instance metadata. Set to <code>disabled</code> to turn off access to instance tags from the instance metadata. For more information, see <a href="https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/Using_Tags.html#work-with-tags-in-IMDS">Work with instance tags using the instance metadata</a>.</p>
    pub instance_metadata_tags: ::std::option::Option<crate::types::InstanceMetadataTagsState>,
}
impl ModifyInstanceMetadataOptionsInput {
    /// <p>The ID of the instance.</p>
    pub fn instance_id(&self) -> ::std::option::Option<&str> {
        self.instance_id.as_deref()
    }
    /// <p>Indicates whether IMDSv2 is required.</p>
    /// <ul>
    /// <li>
    /// <p><code>optional</code> - IMDSv2 is optional. You can choose whether to send a session token in your instance metadata retrieval requests. If you retrieve IAM role credentials without a session token, you receive the IMDSv1 role credentials. If you retrieve IAM role credentials using a valid session token, you receive the IMDSv2 role credentials.</p></li>
    /// <li>
    /// <p><code>required</code> - IMDSv2 is required. You must send a session token in your instance metadata retrieval requests. With this option, retrieving the IAM role credentials always returns IMDSv2 credentials; IMDSv1 credentials are not available.</p></li>
    /// </ul>
    /// <p>Default:</p>
    /// <ul>
    /// <li>
    /// <p>If the value of <code>ImdsSupport</code> for the Amazon Machine Image (AMI) for your instance is <code>v2.0</code> and the account level default is set to <code>no-preference</code>, the default is <code>required</code>.</p></li>
    /// <li>
    /// <p>If the value of <code>ImdsSupport</code> for the Amazon Machine Image (AMI) for your instance is <code>v2.0</code>, but the account level default is set to <code>V1 or V2</code>, the default is <code>optional</code>.</p></li>
    /// </ul>
    /// <p>The default value can also be affected by other combinations of parameters. For more information, see <a href="https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-options.html#instance-metadata-options-order-of-precedence">Order of precedence for instance metadata options</a> in the <i>Amazon EC2 User Guide</i>.</p>
    pub fn http_tokens(&self) -> ::std::option::Option<&crate::types::HttpTokensState> {
        self.http_tokens.as_ref()
    }
    /// <p>The desired HTTP PUT response hop limit for instance metadata requests. The larger the number, the further instance metadata requests can travel. If no parameter is specified, the existing state is maintained.</p>
    /// <p>Possible values: Integers from 1 to 64</p>
    pub fn http_put_response_hop_limit(&self) -> ::std::option::Option<i32> {
        self.http_put_response_hop_limit
    }
    /// <p>Enables or disables the HTTP metadata endpoint on your instances. If this parameter is not specified, the existing state is maintained.</p>
    /// <p>If you specify a value of <code>disabled</code>, you cannot access your instance metadata.</p>
    pub fn http_endpoint(&self) -> ::std::option::Option<&crate::types::InstanceMetadataEndpointState> {
        self.http_endpoint.as_ref()
    }
    /// <p>Checks whether you have the required permissions for the action, without actually making the request, and provides an error response. If you have the required permissions, the error response is <code>DryRunOperation</code>. Otherwise, it is <code>UnauthorizedOperation</code>.</p>
    pub fn dry_run(&self) -> ::std::option::Option<bool> {
        self.dry_run
    }
    /// <p>Enables or disables the IPv6 endpoint for the instance metadata service. Applies only if you enabled the HTTP metadata endpoint.</p>
    pub fn http_protocol_ipv6(&self) -> ::std::option::Option<&crate::types::InstanceMetadataProtocolState> {
        self.http_protocol_ipv6.as_ref()
    }
    /// <p>Set to <code>enabled</code> to allow access to instance tags from the instance metadata. Set to <code>disabled</code> to turn off access to instance tags from the instance metadata. For more information, see <a href="https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/Using_Tags.html#work-with-tags-in-IMDS">Work with instance tags using the instance metadata</a>.</p>
    pub fn instance_metadata_tags(&self) -> ::std::option::Option<&crate::types::InstanceMetadataTagsState> {
        self.instance_metadata_tags.as_ref()
    }
}
impl ModifyInstanceMetadataOptionsInput {
    /// Creates a new builder-style object to manufacture [`ModifyInstanceMetadataOptionsInput`](crate::operation::modify_instance_metadata_options::ModifyInstanceMetadataOptionsInput).
    pub fn builder() -> crate::operation::modify_instance_metadata_options::builders::ModifyInstanceMetadataOptionsInputBuilder {
        crate::operation::modify_instance_metadata_options::builders::ModifyInstanceMetadataOptionsInputBuilder::default()
    }
}

/// A builder for [`ModifyInstanceMetadataOptionsInput`](crate::operation::modify_instance_metadata_options::ModifyInstanceMetadataOptionsInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ModifyInstanceMetadataOptionsInputBuilder {
    pub(crate) instance_id: ::std::option::Option<::std::string::String>,
    pub(crate) http_tokens: ::std::option::Option<crate::types::HttpTokensState>,
    pub(crate) http_put_response_hop_limit: ::std::option::Option<i32>,
    pub(crate) http_endpoint: ::std::option::Option<crate::types::InstanceMetadataEndpointState>,
    pub(crate) dry_run: ::std::option::Option<bool>,
    pub(crate) http_protocol_ipv6: ::std::option::Option<crate::types::InstanceMetadataProtocolState>,
    pub(crate) instance_metadata_tags: ::std::option::Option<crate::types::InstanceMetadataTagsState>,
}
impl ModifyInstanceMetadataOptionsInputBuilder {
    /// <p>The ID of the instance.</p>
    /// This field is required.
    pub fn instance_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.instance_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the instance.</p>
    pub fn set_instance_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.instance_id = input;
        self
    }
    /// <p>The ID of the instance.</p>
    pub fn get_instance_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.instance_id
    }
    /// <p>Indicates whether IMDSv2 is required.</p>
    /// <ul>
    /// <li>
    /// <p><code>optional</code> - IMDSv2 is optional. You can choose whether to send a session token in your instance metadata retrieval requests. If you retrieve IAM role credentials without a session token, you receive the IMDSv1 role credentials. If you retrieve IAM role credentials using a valid session token, you receive the IMDSv2 role credentials.</p></li>
    /// <li>
    /// <p><code>required</code> - IMDSv2 is required. You must send a session token in your instance metadata retrieval requests. With this option, retrieving the IAM role credentials always returns IMDSv2 credentials; IMDSv1 credentials are not available.</p></li>
    /// </ul>
    /// <p>Default:</p>
    /// <ul>
    /// <li>
    /// <p>If the value of <code>ImdsSupport</code> for the Amazon Machine Image (AMI) for your instance is <code>v2.0</code> and the account level default is set to <code>no-preference</code>, the default is <code>required</code>.</p></li>
    /// <li>
    /// <p>If the value of <code>ImdsSupport</code> for the Amazon Machine Image (AMI) for your instance is <code>v2.0</code>, but the account level default is set to <code>V1 or V2</code>, the default is <code>optional</code>.</p></li>
    /// </ul>
    /// <p>The default value can also be affected by other combinations of parameters. For more information, see <a href="https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-options.html#instance-metadata-options-order-of-precedence">Order of precedence for instance metadata options</a> in the <i>Amazon EC2 User Guide</i>.</p>
    pub fn http_tokens(mut self, input: crate::types::HttpTokensState) -> Self {
        self.http_tokens = ::std::option::Option::Some(input);
        self
    }
    /// <p>Indicates whether IMDSv2 is required.</p>
    /// <ul>
    /// <li>
    /// <p><code>optional</code> - IMDSv2 is optional. You can choose whether to send a session token in your instance metadata retrieval requests. If you retrieve IAM role credentials without a session token, you receive the IMDSv1 role credentials. If you retrieve IAM role credentials using a valid session token, you receive the IMDSv2 role credentials.</p></li>
    /// <li>
    /// <p><code>required</code> - IMDSv2 is required. You must send a session token in your instance metadata retrieval requests. With this option, retrieving the IAM role credentials always returns IMDSv2 credentials; IMDSv1 credentials are not available.</p></li>
    /// </ul>
    /// <p>Default:</p>
    /// <ul>
    /// <li>
    /// <p>If the value of <code>ImdsSupport</code> for the Amazon Machine Image (AMI) for your instance is <code>v2.0</code> and the account level default is set to <code>no-preference</code>, the default is <code>required</code>.</p></li>
    /// <li>
    /// <p>If the value of <code>ImdsSupport</code> for the Amazon Machine Image (AMI) for your instance is <code>v2.0</code>, but the account level default is set to <code>V1 or V2</code>, the default is <code>optional</code>.</p></li>
    /// </ul>
    /// <p>The default value can also be affected by other combinations of parameters. For more information, see <a href="https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-options.html#instance-metadata-options-order-of-precedence">Order of precedence for instance metadata options</a> in the <i>Amazon EC2 User Guide</i>.</p>
    pub fn set_http_tokens(mut self, input: ::std::option::Option<crate::types::HttpTokensState>) -> Self {
        self.http_tokens = input;
        self
    }
    /// <p>Indicates whether IMDSv2 is required.</p>
    /// <ul>
    /// <li>
    /// <p><code>optional</code> - IMDSv2 is optional. You can choose whether to send a session token in your instance metadata retrieval requests. If you retrieve IAM role credentials without a session token, you receive the IMDSv1 role credentials. If you retrieve IAM role credentials using a valid session token, you receive the IMDSv2 role credentials.</p></li>
    /// <li>
    /// <p><code>required</code> - IMDSv2 is required. You must send a session token in your instance metadata retrieval requests. With this option, retrieving the IAM role credentials always returns IMDSv2 credentials; IMDSv1 credentials are not available.</p></li>
    /// </ul>
    /// <p>Default:</p>
    /// <ul>
    /// <li>
    /// <p>If the value of <code>ImdsSupport</code> for the Amazon Machine Image (AMI) for your instance is <code>v2.0</code> and the account level default is set to <code>no-preference</code>, the default is <code>required</code>.</p></li>
    /// <li>
    /// <p>If the value of <code>ImdsSupport</code> for the Amazon Machine Image (AMI) for your instance is <code>v2.0</code>, but the account level default is set to <code>V1 or V2</code>, the default is <code>optional</code>.</p></li>
    /// </ul>
    /// <p>The default value can also be affected by other combinations of parameters. For more information, see <a href="https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-options.html#instance-metadata-options-order-of-precedence">Order of precedence for instance metadata options</a> in the <i>Amazon EC2 User Guide</i>.</p>
    pub fn get_http_tokens(&self) -> &::std::option::Option<crate::types::HttpTokensState> {
        &self.http_tokens
    }
    /// <p>The desired HTTP PUT response hop limit for instance metadata requests. The larger the number, the further instance metadata requests can travel. If no parameter is specified, the existing state is maintained.</p>
    /// <p>Possible values: Integers from 1 to 64</p>
    pub fn http_put_response_hop_limit(mut self, input: i32) -> Self {
        self.http_put_response_hop_limit = ::std::option::Option::Some(input);
        self
    }
    /// <p>The desired HTTP PUT response hop limit for instance metadata requests. The larger the number, the further instance metadata requests can travel. If no parameter is specified, the existing state is maintained.</p>
    /// <p>Possible values: Integers from 1 to 64</p>
    pub fn set_http_put_response_hop_limit(mut self, input: ::std::option::Option<i32>) -> Self {
        self.http_put_response_hop_limit = input;
        self
    }
    /// <p>The desired HTTP PUT response hop limit for instance metadata requests. The larger the number, the further instance metadata requests can travel. If no parameter is specified, the existing state is maintained.</p>
    /// <p>Possible values: Integers from 1 to 64</p>
    pub fn get_http_put_response_hop_limit(&self) -> &::std::option::Option<i32> {
        &self.http_put_response_hop_limit
    }
    /// <p>Enables or disables the HTTP metadata endpoint on your instances. If this parameter is not specified, the existing state is maintained.</p>
    /// <p>If you specify a value of <code>disabled</code>, you cannot access your instance metadata.</p>
    pub fn http_endpoint(mut self, input: crate::types::InstanceMetadataEndpointState) -> Self {
        self.http_endpoint = ::std::option::Option::Some(input);
        self
    }
    /// <p>Enables or disables the HTTP metadata endpoint on your instances. If this parameter is not specified, the existing state is maintained.</p>
    /// <p>If you specify a value of <code>disabled</code>, you cannot access your instance metadata.</p>
    pub fn set_http_endpoint(mut self, input: ::std::option::Option<crate::types::InstanceMetadataEndpointState>) -> Self {
        self.http_endpoint = input;
        self
    }
    /// <p>Enables or disables the HTTP metadata endpoint on your instances. If this parameter is not specified, the existing state is maintained.</p>
    /// <p>If you specify a value of <code>disabled</code>, you cannot access your instance metadata.</p>
    pub fn get_http_endpoint(&self) -> &::std::option::Option<crate::types::InstanceMetadataEndpointState> {
        &self.http_endpoint
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
    /// <p>Enables or disables the IPv6 endpoint for the instance metadata service. Applies only if you enabled the HTTP metadata endpoint.</p>
    pub fn http_protocol_ipv6(mut self, input: crate::types::InstanceMetadataProtocolState) -> Self {
        self.http_protocol_ipv6 = ::std::option::Option::Some(input);
        self
    }
    /// <p>Enables or disables the IPv6 endpoint for the instance metadata service. Applies only if you enabled the HTTP metadata endpoint.</p>
    pub fn set_http_protocol_ipv6(mut self, input: ::std::option::Option<crate::types::InstanceMetadataProtocolState>) -> Self {
        self.http_protocol_ipv6 = input;
        self
    }
    /// <p>Enables or disables the IPv6 endpoint for the instance metadata service. Applies only if you enabled the HTTP metadata endpoint.</p>
    pub fn get_http_protocol_ipv6(&self) -> &::std::option::Option<crate::types::InstanceMetadataProtocolState> {
        &self.http_protocol_ipv6
    }
    /// <p>Set to <code>enabled</code> to allow access to instance tags from the instance metadata. Set to <code>disabled</code> to turn off access to instance tags from the instance metadata. For more information, see <a href="https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/Using_Tags.html#work-with-tags-in-IMDS">Work with instance tags using the instance metadata</a>.</p>
    pub fn instance_metadata_tags(mut self, input: crate::types::InstanceMetadataTagsState) -> Self {
        self.instance_metadata_tags = ::std::option::Option::Some(input);
        self
    }
    /// <p>Set to <code>enabled</code> to allow access to instance tags from the instance metadata. Set to <code>disabled</code> to turn off access to instance tags from the instance metadata. For more information, see <a href="https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/Using_Tags.html#work-with-tags-in-IMDS">Work with instance tags using the instance metadata</a>.</p>
    pub fn set_instance_metadata_tags(mut self, input: ::std::option::Option<crate::types::InstanceMetadataTagsState>) -> Self {
        self.instance_metadata_tags = input;
        self
    }
    /// <p>Set to <code>enabled</code> to allow access to instance tags from the instance metadata. Set to <code>disabled</code> to turn off access to instance tags from the instance metadata. For more information, see <a href="https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/Using_Tags.html#work-with-tags-in-IMDS">Work with instance tags using the instance metadata</a>.</p>
    pub fn get_instance_metadata_tags(&self) -> &::std::option::Option<crate::types::InstanceMetadataTagsState> {
        &self.instance_metadata_tags
    }
    /// Consumes the builder and constructs a [`ModifyInstanceMetadataOptionsInput`](crate::operation::modify_instance_metadata_options::ModifyInstanceMetadataOptionsInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::modify_instance_metadata_options::ModifyInstanceMetadataOptionsInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::modify_instance_metadata_options::ModifyInstanceMetadataOptionsInput {
            instance_id: self.instance_id,
            http_tokens: self.http_tokens,
            http_put_response_hop_limit: self.http_put_response_hop_limit,
            http_endpoint: self.http_endpoint,
            dry_run: self.dry_run,
            http_protocol_ipv6: self.http_protocol_ipv6,
            instance_metadata_tags: self.instance_metadata_tags,
        })
    }
}
