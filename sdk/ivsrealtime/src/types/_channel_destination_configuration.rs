// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Object specifying a channel as a destination.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ChannelDestinationConfiguration {
    /// <p>ARN of the channel to use for broadcasting. The channel and stage resources must be in the same AWS account and region. The channel must be offline (not broadcasting).</p>
    pub channel_arn: ::std::string::String,
    /// <p>ARN of the <code>EncoderConfiguration</code> resource. The encoder configuration and stage resources must be in the same AWS account and region.</p>
    pub encoder_configuration_arn: ::std::option::Option<::std::string::String>,
}
impl ChannelDestinationConfiguration {
    /// <p>ARN of the channel to use for broadcasting. The channel and stage resources must be in the same AWS account and region. The channel must be offline (not broadcasting).</p>
    pub fn channel_arn(&self) -> &str {
        use std::ops::Deref;
        self.channel_arn.deref()
    }
    /// <p>ARN of the <code>EncoderConfiguration</code> resource. The encoder configuration and stage resources must be in the same AWS account and region.</p>
    pub fn encoder_configuration_arn(&self) -> ::std::option::Option<&str> {
        self.encoder_configuration_arn.as_deref()
    }
}
impl ChannelDestinationConfiguration {
    /// Creates a new builder-style object to manufacture [`ChannelDestinationConfiguration`](crate::types::ChannelDestinationConfiguration).
    pub fn builder() -> crate::types::builders::ChannelDestinationConfigurationBuilder {
        crate::types::builders::ChannelDestinationConfigurationBuilder::default()
    }
}

/// A builder for [`ChannelDestinationConfiguration`](crate::types::ChannelDestinationConfiguration).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ChannelDestinationConfigurationBuilder {
    pub(crate) channel_arn: ::std::option::Option<::std::string::String>,
    pub(crate) encoder_configuration_arn: ::std::option::Option<::std::string::String>,
}
impl ChannelDestinationConfigurationBuilder {
    /// <p>ARN of the channel to use for broadcasting. The channel and stage resources must be in the same AWS account and region. The channel must be offline (not broadcasting).</p>
    /// This field is required.
    pub fn channel_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.channel_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>ARN of the channel to use for broadcasting. The channel and stage resources must be in the same AWS account and region. The channel must be offline (not broadcasting).</p>
    pub fn set_channel_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.channel_arn = input;
        self
    }
    /// <p>ARN of the channel to use for broadcasting. The channel and stage resources must be in the same AWS account and region. The channel must be offline (not broadcasting).</p>
    pub fn get_channel_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.channel_arn
    }
    /// <p>ARN of the <code>EncoderConfiguration</code> resource. The encoder configuration and stage resources must be in the same AWS account and region.</p>
    pub fn encoder_configuration_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.encoder_configuration_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>ARN of the <code>EncoderConfiguration</code> resource. The encoder configuration and stage resources must be in the same AWS account and region.</p>
    pub fn set_encoder_configuration_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.encoder_configuration_arn = input;
        self
    }
    /// <p>ARN of the <code>EncoderConfiguration</code> resource. The encoder configuration and stage resources must be in the same AWS account and region.</p>
    pub fn get_encoder_configuration_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.encoder_configuration_arn
    }
    /// Consumes the builder and constructs a [`ChannelDestinationConfiguration`](crate::types::ChannelDestinationConfiguration).
    /// This method will fail if any of the following fields are not set:
    /// - [`channel_arn`](crate::types::builders::ChannelDestinationConfigurationBuilder::channel_arn)
    pub fn build(self) -> ::std::result::Result<crate::types::ChannelDestinationConfiguration, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::ChannelDestinationConfiguration {
            channel_arn: self.channel_arn.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "channel_arn",
                    "channel_arn was not specified but it is required when building ChannelDestinationConfiguration",
                )
            })?,
            encoder_configuration_arn: self.encoder_configuration_arn,
        })
    }
}
