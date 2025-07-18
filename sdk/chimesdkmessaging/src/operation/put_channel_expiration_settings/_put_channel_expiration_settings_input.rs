// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct PutChannelExpirationSettingsInput {
    /// <p>The ARN of the channel.</p>
    pub channel_arn: ::std::option::Option<::std::string::String>,
    /// <p>The ARN of the <code>AppInstanceUser</code> or <code>AppInstanceBot</code> that makes the API call.</p>
    pub chime_bearer: ::std::option::Option<::std::string::String>,
    /// <p>Settings that control the interval after which a channel is deleted.</p>
    pub expiration_settings: ::std::option::Option<crate::types::ExpirationSettings>,
}
impl PutChannelExpirationSettingsInput {
    /// <p>The ARN of the channel.</p>
    pub fn channel_arn(&self) -> ::std::option::Option<&str> {
        self.channel_arn.as_deref()
    }
    /// <p>The ARN of the <code>AppInstanceUser</code> or <code>AppInstanceBot</code> that makes the API call.</p>
    pub fn chime_bearer(&self) -> ::std::option::Option<&str> {
        self.chime_bearer.as_deref()
    }
    /// <p>Settings that control the interval after which a channel is deleted.</p>
    pub fn expiration_settings(&self) -> ::std::option::Option<&crate::types::ExpirationSettings> {
        self.expiration_settings.as_ref()
    }
}
impl PutChannelExpirationSettingsInput {
    /// Creates a new builder-style object to manufacture [`PutChannelExpirationSettingsInput`](crate::operation::put_channel_expiration_settings::PutChannelExpirationSettingsInput).
    pub fn builder() -> crate::operation::put_channel_expiration_settings::builders::PutChannelExpirationSettingsInputBuilder {
        crate::operation::put_channel_expiration_settings::builders::PutChannelExpirationSettingsInputBuilder::default()
    }
}

/// A builder for [`PutChannelExpirationSettingsInput`](crate::operation::put_channel_expiration_settings::PutChannelExpirationSettingsInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct PutChannelExpirationSettingsInputBuilder {
    pub(crate) channel_arn: ::std::option::Option<::std::string::String>,
    pub(crate) chime_bearer: ::std::option::Option<::std::string::String>,
    pub(crate) expiration_settings: ::std::option::Option<crate::types::ExpirationSettings>,
}
impl PutChannelExpirationSettingsInputBuilder {
    /// <p>The ARN of the channel.</p>
    /// This field is required.
    pub fn channel_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.channel_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ARN of the channel.</p>
    pub fn set_channel_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.channel_arn = input;
        self
    }
    /// <p>The ARN of the channel.</p>
    pub fn get_channel_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.channel_arn
    }
    /// <p>The ARN of the <code>AppInstanceUser</code> or <code>AppInstanceBot</code> that makes the API call.</p>
    pub fn chime_bearer(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.chime_bearer = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ARN of the <code>AppInstanceUser</code> or <code>AppInstanceBot</code> that makes the API call.</p>
    pub fn set_chime_bearer(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.chime_bearer = input;
        self
    }
    /// <p>The ARN of the <code>AppInstanceUser</code> or <code>AppInstanceBot</code> that makes the API call.</p>
    pub fn get_chime_bearer(&self) -> &::std::option::Option<::std::string::String> {
        &self.chime_bearer
    }
    /// <p>Settings that control the interval after which a channel is deleted.</p>
    pub fn expiration_settings(mut self, input: crate::types::ExpirationSettings) -> Self {
        self.expiration_settings = ::std::option::Option::Some(input);
        self
    }
    /// <p>Settings that control the interval after which a channel is deleted.</p>
    pub fn set_expiration_settings(mut self, input: ::std::option::Option<crate::types::ExpirationSettings>) -> Self {
        self.expiration_settings = input;
        self
    }
    /// <p>Settings that control the interval after which a channel is deleted.</p>
    pub fn get_expiration_settings(&self) -> &::std::option::Option<crate::types::ExpirationSettings> {
        &self.expiration_settings
    }
    /// Consumes the builder and constructs a [`PutChannelExpirationSettingsInput`](crate::operation::put_channel_expiration_settings::PutChannelExpirationSettingsInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::put_channel_expiration_settings::PutChannelExpirationSettingsInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::put_channel_expiration_settings::PutChannelExpirationSettingsInput {
            channel_arn: self.channel_arn,
            chime_bearer: self.chime_bearer,
            expiration_settings: self.expiration_settings,
        })
    }
}
