// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UpdateChannelInput {
    /// <p>The name of the channel to be updated.</p>
    pub channel_name: ::std::option::Option<::std::string::String>,
    /// <p>Where channel data is stored. You can choose one of <code>serviceManagedS3</code> or <code>customerManagedS3</code> storage. If not specified, the default is <code>serviceManagedS3</code>. You can't change this storage option after the channel is created.</p>
    pub channel_storage: ::std::option::Option<crate::types::ChannelStorage>,
    /// <p>How long, in days, message data is kept for the channel. The retention period can't be updated if the channel's Amazon S3 storage is customer-managed.</p>
    pub retention_period: ::std::option::Option<crate::types::RetentionPeriod>,
}
impl UpdateChannelInput {
    /// <p>The name of the channel to be updated.</p>
    pub fn channel_name(&self) -> ::std::option::Option<&str> {
        self.channel_name.as_deref()
    }
    /// <p>Where channel data is stored. You can choose one of <code>serviceManagedS3</code> or <code>customerManagedS3</code> storage. If not specified, the default is <code>serviceManagedS3</code>. You can't change this storage option after the channel is created.</p>
    pub fn channel_storage(&self) -> ::std::option::Option<&crate::types::ChannelStorage> {
        self.channel_storage.as_ref()
    }
    /// <p>How long, in days, message data is kept for the channel. The retention period can't be updated if the channel's Amazon S3 storage is customer-managed.</p>
    pub fn retention_period(&self) -> ::std::option::Option<&crate::types::RetentionPeriod> {
        self.retention_period.as_ref()
    }
}
impl UpdateChannelInput {
    /// Creates a new builder-style object to manufacture [`UpdateChannelInput`](crate::operation::update_channel::UpdateChannelInput).
    pub fn builder() -> crate::operation::update_channel::builders::UpdateChannelInputBuilder {
        crate::operation::update_channel::builders::UpdateChannelInputBuilder::default()
    }
}

/// A builder for [`UpdateChannelInput`](crate::operation::update_channel::UpdateChannelInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UpdateChannelInputBuilder {
    pub(crate) channel_name: ::std::option::Option<::std::string::String>,
    pub(crate) channel_storage: ::std::option::Option<crate::types::ChannelStorage>,
    pub(crate) retention_period: ::std::option::Option<crate::types::RetentionPeriod>,
}
impl UpdateChannelInputBuilder {
    /// <p>The name of the channel to be updated.</p>
    /// This field is required.
    pub fn channel_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.channel_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the channel to be updated.</p>
    pub fn set_channel_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.channel_name = input;
        self
    }
    /// <p>The name of the channel to be updated.</p>
    pub fn get_channel_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.channel_name
    }
    /// <p>Where channel data is stored. You can choose one of <code>serviceManagedS3</code> or <code>customerManagedS3</code> storage. If not specified, the default is <code>serviceManagedS3</code>. You can't change this storage option after the channel is created.</p>
    pub fn channel_storage(mut self, input: crate::types::ChannelStorage) -> Self {
        self.channel_storage = ::std::option::Option::Some(input);
        self
    }
    /// <p>Where channel data is stored. You can choose one of <code>serviceManagedS3</code> or <code>customerManagedS3</code> storage. If not specified, the default is <code>serviceManagedS3</code>. You can't change this storage option after the channel is created.</p>
    pub fn set_channel_storage(mut self, input: ::std::option::Option<crate::types::ChannelStorage>) -> Self {
        self.channel_storage = input;
        self
    }
    /// <p>Where channel data is stored. You can choose one of <code>serviceManagedS3</code> or <code>customerManagedS3</code> storage. If not specified, the default is <code>serviceManagedS3</code>. You can't change this storage option after the channel is created.</p>
    pub fn get_channel_storage(&self) -> &::std::option::Option<crate::types::ChannelStorage> {
        &self.channel_storage
    }
    /// <p>How long, in days, message data is kept for the channel. The retention period can't be updated if the channel's Amazon S3 storage is customer-managed.</p>
    pub fn retention_period(mut self, input: crate::types::RetentionPeriod) -> Self {
        self.retention_period = ::std::option::Option::Some(input);
        self
    }
    /// <p>How long, in days, message data is kept for the channel. The retention period can't be updated if the channel's Amazon S3 storage is customer-managed.</p>
    pub fn set_retention_period(mut self, input: ::std::option::Option<crate::types::RetentionPeriod>) -> Self {
        self.retention_period = input;
        self
    }
    /// <p>How long, in days, message data is kept for the channel. The retention period can't be updated if the channel's Amazon S3 storage is customer-managed.</p>
    pub fn get_retention_period(&self) -> &::std::option::Option<crate::types::RetentionPeriod> {
        &self.retention_period
    }
    /// Consumes the builder and constructs a [`UpdateChannelInput`](crate::operation::update_channel::UpdateChannelInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::update_channel::UpdateChannelInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::update_channel::UpdateChannelInput {
            channel_name: self.channel_name,
            channel_storage: self.channel_storage,
            retention_period: self.retention_period,
        })
    }
}
