// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ModifyInstanceMetadataDefaultsInput {
    /// <p>Indicates whether IMDSv2 is required.</p>
    /// <ul>
    /// <li>
    /// <p><code>optional</code> – IMDSv2 is optional, which means that you can use either IMDSv2 or IMDSv1.</p></li>
    /// <li>
    /// <p><code>required</code> – IMDSv2 is required, which means that IMDSv1 is disabled, and you must use IMDSv2.</p></li>
    /// </ul>
    pub http_tokens: ::std::option::Option<crate::types::MetadataDefaultHttpTokensState>,
    /// <p>The maximum number of hops that the metadata token can travel. To indicate no preference, specify <code>-1</code>.</p>
    /// <p>Possible values: Integers from <code>1</code> to <code>64</code>, and <code>-1</code> to indicate no preference</p>
    pub http_put_response_hop_limit: ::std::option::Option<i32>,
    /// <p>Enables or disables the IMDS endpoint on an instance. When disabled, the instance metadata can't be accessed.</p>
    pub http_endpoint: ::std::option::Option<crate::types::DefaultInstanceMetadataEndpointState>,
    /// <p>Enables or disables access to an instance's tags from the instance metadata. For more information, see <a href="https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/Using_Tags.html#work-with-tags-in-IMDS">Work with instance tags using the instance metadata</a> in the <i>Amazon EC2 User Guide</i>.</p>
    pub instance_metadata_tags: ::std::option::Option<crate::types::DefaultInstanceMetadataTagsState>,
    /// <p>Checks whether you have the required permissions for the operation, without actually making the request, and provides an error response. If you have the required permissions, the error response is <code>DryRunOperation</code>. Otherwise, it is <code>UnauthorizedOperation</code>.</p>
    pub dry_run: ::std::option::Option<bool>,
}
impl ModifyInstanceMetadataDefaultsInput {
    /// <p>Indicates whether IMDSv2 is required.</p>
    /// <ul>
    /// <li>
    /// <p><code>optional</code> – IMDSv2 is optional, which means that you can use either IMDSv2 or IMDSv1.</p></li>
    /// <li>
    /// <p><code>required</code> – IMDSv2 is required, which means that IMDSv1 is disabled, and you must use IMDSv2.</p></li>
    /// </ul>
    pub fn http_tokens(&self) -> ::std::option::Option<&crate::types::MetadataDefaultHttpTokensState> {
        self.http_tokens.as_ref()
    }
    /// <p>The maximum number of hops that the metadata token can travel. To indicate no preference, specify <code>-1</code>.</p>
    /// <p>Possible values: Integers from <code>1</code> to <code>64</code>, and <code>-1</code> to indicate no preference</p>
    pub fn http_put_response_hop_limit(&self) -> ::std::option::Option<i32> {
        self.http_put_response_hop_limit
    }
    /// <p>Enables or disables the IMDS endpoint on an instance. When disabled, the instance metadata can't be accessed.</p>
    pub fn http_endpoint(&self) -> ::std::option::Option<&crate::types::DefaultInstanceMetadataEndpointState> {
        self.http_endpoint.as_ref()
    }
    /// <p>Enables or disables access to an instance's tags from the instance metadata. For more information, see <a href="https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/Using_Tags.html#work-with-tags-in-IMDS">Work with instance tags using the instance metadata</a> in the <i>Amazon EC2 User Guide</i>.</p>
    pub fn instance_metadata_tags(&self) -> ::std::option::Option<&crate::types::DefaultInstanceMetadataTagsState> {
        self.instance_metadata_tags.as_ref()
    }
    /// <p>Checks whether you have the required permissions for the operation, without actually making the request, and provides an error response. If you have the required permissions, the error response is <code>DryRunOperation</code>. Otherwise, it is <code>UnauthorizedOperation</code>.</p>
    pub fn dry_run(&self) -> ::std::option::Option<bool> {
        self.dry_run
    }
}
impl ModifyInstanceMetadataDefaultsInput {
    /// Creates a new builder-style object to manufacture [`ModifyInstanceMetadataDefaultsInput`](crate::operation::modify_instance_metadata_defaults::ModifyInstanceMetadataDefaultsInput).
    pub fn builder() -> crate::operation::modify_instance_metadata_defaults::builders::ModifyInstanceMetadataDefaultsInputBuilder {
        crate::operation::modify_instance_metadata_defaults::builders::ModifyInstanceMetadataDefaultsInputBuilder::default()
    }
}

/// A builder for [`ModifyInstanceMetadataDefaultsInput`](crate::operation::modify_instance_metadata_defaults::ModifyInstanceMetadataDefaultsInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ModifyInstanceMetadataDefaultsInputBuilder {
    pub(crate) http_tokens: ::std::option::Option<crate::types::MetadataDefaultHttpTokensState>,
    pub(crate) http_put_response_hop_limit: ::std::option::Option<i32>,
    pub(crate) http_endpoint: ::std::option::Option<crate::types::DefaultInstanceMetadataEndpointState>,
    pub(crate) instance_metadata_tags: ::std::option::Option<crate::types::DefaultInstanceMetadataTagsState>,
    pub(crate) dry_run: ::std::option::Option<bool>,
}
impl ModifyInstanceMetadataDefaultsInputBuilder {
    /// <p>Indicates whether IMDSv2 is required.</p>
    /// <ul>
    /// <li>
    /// <p><code>optional</code> – IMDSv2 is optional, which means that you can use either IMDSv2 or IMDSv1.</p></li>
    /// <li>
    /// <p><code>required</code> – IMDSv2 is required, which means that IMDSv1 is disabled, and you must use IMDSv2.</p></li>
    /// </ul>
    pub fn http_tokens(mut self, input: crate::types::MetadataDefaultHttpTokensState) -> Self {
        self.http_tokens = ::std::option::Option::Some(input);
        self
    }
    /// <p>Indicates whether IMDSv2 is required.</p>
    /// <ul>
    /// <li>
    /// <p><code>optional</code> – IMDSv2 is optional, which means that you can use either IMDSv2 or IMDSv1.</p></li>
    /// <li>
    /// <p><code>required</code> – IMDSv2 is required, which means that IMDSv1 is disabled, and you must use IMDSv2.</p></li>
    /// </ul>
    pub fn set_http_tokens(mut self, input: ::std::option::Option<crate::types::MetadataDefaultHttpTokensState>) -> Self {
        self.http_tokens = input;
        self
    }
    /// <p>Indicates whether IMDSv2 is required.</p>
    /// <ul>
    /// <li>
    /// <p><code>optional</code> – IMDSv2 is optional, which means that you can use either IMDSv2 or IMDSv1.</p></li>
    /// <li>
    /// <p><code>required</code> – IMDSv2 is required, which means that IMDSv1 is disabled, and you must use IMDSv2.</p></li>
    /// </ul>
    pub fn get_http_tokens(&self) -> &::std::option::Option<crate::types::MetadataDefaultHttpTokensState> {
        &self.http_tokens
    }
    /// <p>The maximum number of hops that the metadata token can travel. To indicate no preference, specify <code>-1</code>.</p>
    /// <p>Possible values: Integers from <code>1</code> to <code>64</code>, and <code>-1</code> to indicate no preference</p>
    pub fn http_put_response_hop_limit(mut self, input: i32) -> Self {
        self.http_put_response_hop_limit = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum number of hops that the metadata token can travel. To indicate no preference, specify <code>-1</code>.</p>
    /// <p>Possible values: Integers from <code>1</code> to <code>64</code>, and <code>-1</code> to indicate no preference</p>
    pub fn set_http_put_response_hop_limit(mut self, input: ::std::option::Option<i32>) -> Self {
        self.http_put_response_hop_limit = input;
        self
    }
    /// <p>The maximum number of hops that the metadata token can travel. To indicate no preference, specify <code>-1</code>.</p>
    /// <p>Possible values: Integers from <code>1</code> to <code>64</code>, and <code>-1</code> to indicate no preference</p>
    pub fn get_http_put_response_hop_limit(&self) -> &::std::option::Option<i32> {
        &self.http_put_response_hop_limit
    }
    /// <p>Enables or disables the IMDS endpoint on an instance. When disabled, the instance metadata can't be accessed.</p>
    pub fn http_endpoint(mut self, input: crate::types::DefaultInstanceMetadataEndpointState) -> Self {
        self.http_endpoint = ::std::option::Option::Some(input);
        self
    }
    /// <p>Enables or disables the IMDS endpoint on an instance. When disabled, the instance metadata can't be accessed.</p>
    pub fn set_http_endpoint(mut self, input: ::std::option::Option<crate::types::DefaultInstanceMetadataEndpointState>) -> Self {
        self.http_endpoint = input;
        self
    }
    /// <p>Enables or disables the IMDS endpoint on an instance. When disabled, the instance metadata can't be accessed.</p>
    pub fn get_http_endpoint(&self) -> &::std::option::Option<crate::types::DefaultInstanceMetadataEndpointState> {
        &self.http_endpoint
    }
    /// <p>Enables or disables access to an instance's tags from the instance metadata. For more information, see <a href="https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/Using_Tags.html#work-with-tags-in-IMDS">Work with instance tags using the instance metadata</a> in the <i>Amazon EC2 User Guide</i>.</p>
    pub fn instance_metadata_tags(mut self, input: crate::types::DefaultInstanceMetadataTagsState) -> Self {
        self.instance_metadata_tags = ::std::option::Option::Some(input);
        self
    }
    /// <p>Enables or disables access to an instance's tags from the instance metadata. For more information, see <a href="https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/Using_Tags.html#work-with-tags-in-IMDS">Work with instance tags using the instance metadata</a> in the <i>Amazon EC2 User Guide</i>.</p>
    pub fn set_instance_metadata_tags(mut self, input: ::std::option::Option<crate::types::DefaultInstanceMetadataTagsState>) -> Self {
        self.instance_metadata_tags = input;
        self
    }
    /// <p>Enables or disables access to an instance's tags from the instance metadata. For more information, see <a href="https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/Using_Tags.html#work-with-tags-in-IMDS">Work with instance tags using the instance metadata</a> in the <i>Amazon EC2 User Guide</i>.</p>
    pub fn get_instance_metadata_tags(&self) -> &::std::option::Option<crate::types::DefaultInstanceMetadataTagsState> {
        &self.instance_metadata_tags
    }
    /// <p>Checks whether you have the required permissions for the operation, without actually making the request, and provides an error response. If you have the required permissions, the error response is <code>DryRunOperation</code>. Otherwise, it is <code>UnauthorizedOperation</code>.</p>
    pub fn dry_run(mut self, input: bool) -> Self {
        self.dry_run = ::std::option::Option::Some(input);
        self
    }
    /// <p>Checks whether you have the required permissions for the operation, without actually making the request, and provides an error response. If you have the required permissions, the error response is <code>DryRunOperation</code>. Otherwise, it is <code>UnauthorizedOperation</code>.</p>
    pub fn set_dry_run(mut self, input: ::std::option::Option<bool>) -> Self {
        self.dry_run = input;
        self
    }
    /// <p>Checks whether you have the required permissions for the operation, without actually making the request, and provides an error response. If you have the required permissions, the error response is <code>DryRunOperation</code>. Otherwise, it is <code>UnauthorizedOperation</code>.</p>
    pub fn get_dry_run(&self) -> &::std::option::Option<bool> {
        &self.dry_run
    }
    /// Consumes the builder and constructs a [`ModifyInstanceMetadataDefaultsInput`](crate::operation::modify_instance_metadata_defaults::ModifyInstanceMetadataDefaultsInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::modify_instance_metadata_defaults::ModifyInstanceMetadataDefaultsInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::modify_instance_metadata_defaults::ModifyInstanceMetadataDefaultsInput {
            http_tokens: self.http_tokens,
            http_put_response_hop_limit: self.http_put_response_hop_limit,
            http_endpoint: self.http_endpoint,
            instance_metadata_tags: self.instance_metadata_tags,
            dry_run: self.dry_run,
        })
    }
}
