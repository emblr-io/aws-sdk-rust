// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UpdateSignalingChannelInput {
    /// <p>The Amazon Resource Name (ARN) of the signaling channel that you want to update.</p>
    pub channel_arn: ::std::option::Option<::std::string::String>,
    /// <p>The current version of the signaling channel that you want to update.</p>
    pub current_version: ::std::option::Option<::std::string::String>,
    /// <p>The structure containing the configuration for the <code>SINGLE_MASTER</code> type of the signaling channel that you want to update.</p>
    pub single_master_configuration: ::std::option::Option<crate::types::SingleMasterConfiguration>,
}
impl UpdateSignalingChannelInput {
    /// <p>The Amazon Resource Name (ARN) of the signaling channel that you want to update.</p>
    pub fn channel_arn(&self) -> ::std::option::Option<&str> {
        self.channel_arn.as_deref()
    }
    /// <p>The current version of the signaling channel that you want to update.</p>
    pub fn current_version(&self) -> ::std::option::Option<&str> {
        self.current_version.as_deref()
    }
    /// <p>The structure containing the configuration for the <code>SINGLE_MASTER</code> type of the signaling channel that you want to update.</p>
    pub fn single_master_configuration(&self) -> ::std::option::Option<&crate::types::SingleMasterConfiguration> {
        self.single_master_configuration.as_ref()
    }
}
impl UpdateSignalingChannelInput {
    /// Creates a new builder-style object to manufacture [`UpdateSignalingChannelInput`](crate::operation::update_signaling_channel::UpdateSignalingChannelInput).
    pub fn builder() -> crate::operation::update_signaling_channel::builders::UpdateSignalingChannelInputBuilder {
        crate::operation::update_signaling_channel::builders::UpdateSignalingChannelInputBuilder::default()
    }
}

/// A builder for [`UpdateSignalingChannelInput`](crate::operation::update_signaling_channel::UpdateSignalingChannelInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UpdateSignalingChannelInputBuilder {
    pub(crate) channel_arn: ::std::option::Option<::std::string::String>,
    pub(crate) current_version: ::std::option::Option<::std::string::String>,
    pub(crate) single_master_configuration: ::std::option::Option<crate::types::SingleMasterConfiguration>,
}
impl UpdateSignalingChannelInputBuilder {
    /// <p>The Amazon Resource Name (ARN) of the signaling channel that you want to update.</p>
    /// This field is required.
    pub fn channel_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.channel_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the signaling channel that you want to update.</p>
    pub fn set_channel_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.channel_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the signaling channel that you want to update.</p>
    pub fn get_channel_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.channel_arn
    }
    /// <p>The current version of the signaling channel that you want to update.</p>
    /// This field is required.
    pub fn current_version(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.current_version = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The current version of the signaling channel that you want to update.</p>
    pub fn set_current_version(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.current_version = input;
        self
    }
    /// <p>The current version of the signaling channel that you want to update.</p>
    pub fn get_current_version(&self) -> &::std::option::Option<::std::string::String> {
        &self.current_version
    }
    /// <p>The structure containing the configuration for the <code>SINGLE_MASTER</code> type of the signaling channel that you want to update.</p>
    pub fn single_master_configuration(mut self, input: crate::types::SingleMasterConfiguration) -> Self {
        self.single_master_configuration = ::std::option::Option::Some(input);
        self
    }
    /// <p>The structure containing the configuration for the <code>SINGLE_MASTER</code> type of the signaling channel that you want to update.</p>
    pub fn set_single_master_configuration(mut self, input: ::std::option::Option<crate::types::SingleMasterConfiguration>) -> Self {
        self.single_master_configuration = input;
        self
    }
    /// <p>The structure containing the configuration for the <code>SINGLE_MASTER</code> type of the signaling channel that you want to update.</p>
    pub fn get_single_master_configuration(&self) -> &::std::option::Option<crate::types::SingleMasterConfiguration> {
        &self.single_master_configuration
    }
    /// Consumes the builder and constructs a [`UpdateSignalingChannelInput`](crate::operation::update_signaling_channel::UpdateSignalingChannelInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::update_signaling_channel::UpdateSignalingChannelInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::update_signaling_channel::UpdateSignalingChannelInput {
            channel_arn: self.channel_arn,
            current_version: self.current_version,
            single_master_configuration: self.single_master_configuration,
        })
    }
}
