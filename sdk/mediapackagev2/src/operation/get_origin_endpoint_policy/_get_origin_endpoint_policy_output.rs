// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetOriginEndpointPolicyOutput {
    /// <p>The name that describes the channel group. The name is the primary identifier for the channel group, and must be unique for your account in the AWS Region.</p>
    pub channel_group_name: ::std::string::String,
    /// <p>The name that describes the channel. The name is the primary identifier for the channel, and must be unique for your account in the AWS Region and channel group.</p>
    pub channel_name: ::std::string::String,
    /// <p>The name that describes the origin endpoint. The name is the primary identifier for the origin endpoint, and and must be unique for your account in the AWS Region and channel.</p>
    pub origin_endpoint_name: ::std::string::String,
    /// <p>The policy assigned to the origin endpoint.</p>
    pub policy: ::std::string::String,
    _request_id: Option<String>,
}
impl GetOriginEndpointPolicyOutput {
    /// <p>The name that describes the channel group. The name is the primary identifier for the channel group, and must be unique for your account in the AWS Region.</p>
    pub fn channel_group_name(&self) -> &str {
        use std::ops::Deref;
        self.channel_group_name.deref()
    }
    /// <p>The name that describes the channel. The name is the primary identifier for the channel, and must be unique for your account in the AWS Region and channel group.</p>
    pub fn channel_name(&self) -> &str {
        use std::ops::Deref;
        self.channel_name.deref()
    }
    /// <p>The name that describes the origin endpoint. The name is the primary identifier for the origin endpoint, and and must be unique for your account in the AWS Region and channel.</p>
    pub fn origin_endpoint_name(&self) -> &str {
        use std::ops::Deref;
        self.origin_endpoint_name.deref()
    }
    /// <p>The policy assigned to the origin endpoint.</p>
    pub fn policy(&self) -> &str {
        use std::ops::Deref;
        self.policy.deref()
    }
}
impl ::aws_types::request_id::RequestId for GetOriginEndpointPolicyOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl GetOriginEndpointPolicyOutput {
    /// Creates a new builder-style object to manufacture [`GetOriginEndpointPolicyOutput`](crate::operation::get_origin_endpoint_policy::GetOriginEndpointPolicyOutput).
    pub fn builder() -> crate::operation::get_origin_endpoint_policy::builders::GetOriginEndpointPolicyOutputBuilder {
        crate::operation::get_origin_endpoint_policy::builders::GetOriginEndpointPolicyOutputBuilder::default()
    }
}

/// A builder for [`GetOriginEndpointPolicyOutput`](crate::operation::get_origin_endpoint_policy::GetOriginEndpointPolicyOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetOriginEndpointPolicyOutputBuilder {
    pub(crate) channel_group_name: ::std::option::Option<::std::string::String>,
    pub(crate) channel_name: ::std::option::Option<::std::string::String>,
    pub(crate) origin_endpoint_name: ::std::option::Option<::std::string::String>,
    pub(crate) policy: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl GetOriginEndpointPolicyOutputBuilder {
    /// <p>The name that describes the channel group. The name is the primary identifier for the channel group, and must be unique for your account in the AWS Region.</p>
    /// This field is required.
    pub fn channel_group_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.channel_group_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name that describes the channel group. The name is the primary identifier for the channel group, and must be unique for your account in the AWS Region.</p>
    pub fn set_channel_group_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.channel_group_name = input;
        self
    }
    /// <p>The name that describes the channel group. The name is the primary identifier for the channel group, and must be unique for your account in the AWS Region.</p>
    pub fn get_channel_group_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.channel_group_name
    }
    /// <p>The name that describes the channel. The name is the primary identifier for the channel, and must be unique for your account in the AWS Region and channel group.</p>
    /// This field is required.
    pub fn channel_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.channel_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name that describes the channel. The name is the primary identifier for the channel, and must be unique for your account in the AWS Region and channel group.</p>
    pub fn set_channel_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.channel_name = input;
        self
    }
    /// <p>The name that describes the channel. The name is the primary identifier for the channel, and must be unique for your account in the AWS Region and channel group.</p>
    pub fn get_channel_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.channel_name
    }
    /// <p>The name that describes the origin endpoint. The name is the primary identifier for the origin endpoint, and and must be unique for your account in the AWS Region and channel.</p>
    /// This field is required.
    pub fn origin_endpoint_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.origin_endpoint_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name that describes the origin endpoint. The name is the primary identifier for the origin endpoint, and and must be unique for your account in the AWS Region and channel.</p>
    pub fn set_origin_endpoint_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.origin_endpoint_name = input;
        self
    }
    /// <p>The name that describes the origin endpoint. The name is the primary identifier for the origin endpoint, and and must be unique for your account in the AWS Region and channel.</p>
    pub fn get_origin_endpoint_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.origin_endpoint_name
    }
    /// <p>The policy assigned to the origin endpoint.</p>
    /// This field is required.
    pub fn policy(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.policy = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The policy assigned to the origin endpoint.</p>
    pub fn set_policy(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.policy = input;
        self
    }
    /// <p>The policy assigned to the origin endpoint.</p>
    pub fn get_policy(&self) -> &::std::option::Option<::std::string::String> {
        &self.policy
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`GetOriginEndpointPolicyOutput`](crate::operation::get_origin_endpoint_policy::GetOriginEndpointPolicyOutput).
    /// This method will fail if any of the following fields are not set:
    /// - [`channel_group_name`](crate::operation::get_origin_endpoint_policy::builders::GetOriginEndpointPolicyOutputBuilder::channel_group_name)
    /// - [`channel_name`](crate::operation::get_origin_endpoint_policy::builders::GetOriginEndpointPolicyOutputBuilder::channel_name)
    /// - [`origin_endpoint_name`](crate::operation::get_origin_endpoint_policy::builders::GetOriginEndpointPolicyOutputBuilder::origin_endpoint_name)
    /// - [`policy`](crate::operation::get_origin_endpoint_policy::builders::GetOriginEndpointPolicyOutputBuilder::policy)
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::get_origin_endpoint_policy::GetOriginEndpointPolicyOutput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::get_origin_endpoint_policy::GetOriginEndpointPolicyOutput {
            channel_group_name: self.channel_group_name.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "channel_group_name",
                    "channel_group_name was not specified but it is required when building GetOriginEndpointPolicyOutput",
                )
            })?,
            channel_name: self.channel_name.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "channel_name",
                    "channel_name was not specified but it is required when building GetOriginEndpointPolicyOutput",
                )
            })?,
            origin_endpoint_name: self.origin_endpoint_name.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "origin_endpoint_name",
                    "origin_endpoint_name was not specified but it is required when building GetOriginEndpointPolicyOutput",
                )
            })?,
            policy: self.policy.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "policy",
                    "policy was not specified but it is required when building GetOriginEndpointPolicyOutput",
                )
            })?,
            _request_id: self._request_id,
        })
    }
}
