// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ResetOriginEndpointStateOutput {
    /// <p>The name of the channel group that contains the channel with the origin endpoint that you just reset.</p>
    pub channel_group_name: ::std::string::String,
    /// <p>The name of the channel with the origin endpoint that you just reset.</p>
    pub channel_name: ::std::string::String,
    /// <p>The name of the origin endpoint that you just reset.</p>
    pub origin_endpoint_name: ::std::string::String,
    /// <p>The Amazon Resource Name (ARN) associated with the endpoint that you just reset.</p>
    pub arn: ::std::string::String,
    /// <p>The time that the origin endpoint was last reset.</p>
    pub reset_at: ::aws_smithy_types::DateTime,
    _request_id: Option<String>,
}
impl ResetOriginEndpointStateOutput {
    /// <p>The name of the channel group that contains the channel with the origin endpoint that you just reset.</p>
    pub fn channel_group_name(&self) -> &str {
        use std::ops::Deref;
        self.channel_group_name.deref()
    }
    /// <p>The name of the channel with the origin endpoint that you just reset.</p>
    pub fn channel_name(&self) -> &str {
        use std::ops::Deref;
        self.channel_name.deref()
    }
    /// <p>The name of the origin endpoint that you just reset.</p>
    pub fn origin_endpoint_name(&self) -> &str {
        use std::ops::Deref;
        self.origin_endpoint_name.deref()
    }
    /// <p>The Amazon Resource Name (ARN) associated with the endpoint that you just reset.</p>
    pub fn arn(&self) -> &str {
        use std::ops::Deref;
        self.arn.deref()
    }
    /// <p>The time that the origin endpoint was last reset.</p>
    pub fn reset_at(&self) -> &::aws_smithy_types::DateTime {
        &self.reset_at
    }
}
impl ::aws_types::request_id::RequestId for ResetOriginEndpointStateOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl ResetOriginEndpointStateOutput {
    /// Creates a new builder-style object to manufacture [`ResetOriginEndpointStateOutput`](crate::operation::reset_origin_endpoint_state::ResetOriginEndpointStateOutput).
    pub fn builder() -> crate::operation::reset_origin_endpoint_state::builders::ResetOriginEndpointStateOutputBuilder {
        crate::operation::reset_origin_endpoint_state::builders::ResetOriginEndpointStateOutputBuilder::default()
    }
}

/// A builder for [`ResetOriginEndpointStateOutput`](crate::operation::reset_origin_endpoint_state::ResetOriginEndpointStateOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ResetOriginEndpointStateOutputBuilder {
    pub(crate) channel_group_name: ::std::option::Option<::std::string::String>,
    pub(crate) channel_name: ::std::option::Option<::std::string::String>,
    pub(crate) origin_endpoint_name: ::std::option::Option<::std::string::String>,
    pub(crate) arn: ::std::option::Option<::std::string::String>,
    pub(crate) reset_at: ::std::option::Option<::aws_smithy_types::DateTime>,
    _request_id: Option<String>,
}
impl ResetOriginEndpointStateOutputBuilder {
    /// <p>The name of the channel group that contains the channel with the origin endpoint that you just reset.</p>
    /// This field is required.
    pub fn channel_group_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.channel_group_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the channel group that contains the channel with the origin endpoint that you just reset.</p>
    pub fn set_channel_group_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.channel_group_name = input;
        self
    }
    /// <p>The name of the channel group that contains the channel with the origin endpoint that you just reset.</p>
    pub fn get_channel_group_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.channel_group_name
    }
    /// <p>The name of the channel with the origin endpoint that you just reset.</p>
    /// This field is required.
    pub fn channel_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.channel_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the channel with the origin endpoint that you just reset.</p>
    pub fn set_channel_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.channel_name = input;
        self
    }
    /// <p>The name of the channel with the origin endpoint that you just reset.</p>
    pub fn get_channel_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.channel_name
    }
    /// <p>The name of the origin endpoint that you just reset.</p>
    /// This field is required.
    pub fn origin_endpoint_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.origin_endpoint_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the origin endpoint that you just reset.</p>
    pub fn set_origin_endpoint_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.origin_endpoint_name = input;
        self
    }
    /// <p>The name of the origin endpoint that you just reset.</p>
    pub fn get_origin_endpoint_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.origin_endpoint_name
    }
    /// <p>The Amazon Resource Name (ARN) associated with the endpoint that you just reset.</p>
    /// This field is required.
    pub fn arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) associated with the endpoint that you just reset.</p>
    pub fn set_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) associated with the endpoint that you just reset.</p>
    pub fn get_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.arn
    }
    /// <p>The time that the origin endpoint was last reset.</p>
    /// This field is required.
    pub fn reset_at(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.reset_at = ::std::option::Option::Some(input);
        self
    }
    /// <p>The time that the origin endpoint was last reset.</p>
    pub fn set_reset_at(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.reset_at = input;
        self
    }
    /// <p>The time that the origin endpoint was last reset.</p>
    pub fn get_reset_at(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.reset_at
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`ResetOriginEndpointStateOutput`](crate::operation::reset_origin_endpoint_state::ResetOriginEndpointStateOutput).
    /// This method will fail if any of the following fields are not set:
    /// - [`channel_group_name`](crate::operation::reset_origin_endpoint_state::builders::ResetOriginEndpointStateOutputBuilder::channel_group_name)
    /// - [`channel_name`](crate::operation::reset_origin_endpoint_state::builders::ResetOriginEndpointStateOutputBuilder::channel_name)
    /// - [`origin_endpoint_name`](crate::operation::reset_origin_endpoint_state::builders::ResetOriginEndpointStateOutputBuilder::origin_endpoint_name)
    /// - [`arn`](crate::operation::reset_origin_endpoint_state::builders::ResetOriginEndpointStateOutputBuilder::arn)
    /// - [`reset_at`](crate::operation::reset_origin_endpoint_state::builders::ResetOriginEndpointStateOutputBuilder::reset_at)
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::reset_origin_endpoint_state::ResetOriginEndpointStateOutput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::reset_origin_endpoint_state::ResetOriginEndpointStateOutput {
            channel_group_name: self.channel_group_name.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "channel_group_name",
                    "channel_group_name was not specified but it is required when building ResetOriginEndpointStateOutput",
                )
            })?,
            channel_name: self.channel_name.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "channel_name",
                    "channel_name was not specified but it is required when building ResetOriginEndpointStateOutput",
                )
            })?,
            origin_endpoint_name: self.origin_endpoint_name.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "origin_endpoint_name",
                    "origin_endpoint_name was not specified but it is required when building ResetOriginEndpointStateOutput",
                )
            })?,
            arn: self.arn.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "arn",
                    "arn was not specified but it is required when building ResetOriginEndpointStateOutput",
                )
            })?,
            reset_at: self.reset_at.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "reset_at",
                    "reset_at was not specified but it is required when building ResetOriginEndpointStateOutput",
                )
            })?,
            _request_id: self._request_id,
        })
    }
}
