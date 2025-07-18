// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetBotChannelAssociationInput {
    /// <p>The name of the association between the bot and the channel. The name is case sensitive.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>The name of the Amazon Lex bot.</p>
    pub bot_name: ::std::option::Option<::std::string::String>,
    /// <p>An alias pointing to the specific version of the Amazon Lex bot to which this association is being made.</p>
    pub bot_alias: ::std::option::Option<::std::string::String>,
}
impl GetBotChannelAssociationInput {
    /// <p>The name of the association between the bot and the channel. The name is case sensitive.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>The name of the Amazon Lex bot.</p>
    pub fn bot_name(&self) -> ::std::option::Option<&str> {
        self.bot_name.as_deref()
    }
    /// <p>An alias pointing to the specific version of the Amazon Lex bot to which this association is being made.</p>
    pub fn bot_alias(&self) -> ::std::option::Option<&str> {
        self.bot_alias.as_deref()
    }
}
impl GetBotChannelAssociationInput {
    /// Creates a new builder-style object to manufacture [`GetBotChannelAssociationInput`](crate::operation::get_bot_channel_association::GetBotChannelAssociationInput).
    pub fn builder() -> crate::operation::get_bot_channel_association::builders::GetBotChannelAssociationInputBuilder {
        crate::operation::get_bot_channel_association::builders::GetBotChannelAssociationInputBuilder::default()
    }
}

/// A builder for [`GetBotChannelAssociationInput`](crate::operation::get_bot_channel_association::GetBotChannelAssociationInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetBotChannelAssociationInputBuilder {
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) bot_name: ::std::option::Option<::std::string::String>,
    pub(crate) bot_alias: ::std::option::Option<::std::string::String>,
}
impl GetBotChannelAssociationInputBuilder {
    /// <p>The name of the association between the bot and the channel. The name is case sensitive.</p>
    /// This field is required.
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the association between the bot and the channel. The name is case sensitive.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the association between the bot and the channel. The name is case sensitive.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>The name of the Amazon Lex bot.</p>
    /// This field is required.
    pub fn bot_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.bot_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the Amazon Lex bot.</p>
    pub fn set_bot_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.bot_name = input;
        self
    }
    /// <p>The name of the Amazon Lex bot.</p>
    pub fn get_bot_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.bot_name
    }
    /// <p>An alias pointing to the specific version of the Amazon Lex bot to which this association is being made.</p>
    /// This field is required.
    pub fn bot_alias(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.bot_alias = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>An alias pointing to the specific version of the Amazon Lex bot to which this association is being made.</p>
    pub fn set_bot_alias(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.bot_alias = input;
        self
    }
    /// <p>An alias pointing to the specific version of the Amazon Lex bot to which this association is being made.</p>
    pub fn get_bot_alias(&self) -> &::std::option::Option<::std::string::String> {
        &self.bot_alias
    }
    /// Consumes the builder and constructs a [`GetBotChannelAssociationInput`](crate::operation::get_bot_channel_association::GetBotChannelAssociationInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::get_bot_channel_association::GetBotChannelAssociationInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::get_bot_channel_association::GetBotChannelAssociationInput {
            name: self.name,
            bot_name: self.bot_name,
            bot_alias: self.bot_alias,
        })
    }
}
