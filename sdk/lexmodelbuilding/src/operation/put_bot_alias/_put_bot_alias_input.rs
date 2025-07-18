// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct PutBotAliasInput {
    /// <p>The name of the alias. The name is <i>not</i> case sensitive.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>A description of the alias.</p>
    pub description: ::std::option::Option<::std::string::String>,
    /// <p>The version of the bot.</p>
    pub bot_version: ::std::option::Option<::std::string::String>,
    /// <p>The name of the bot.</p>
    pub bot_name: ::std::option::Option<::std::string::String>,
    /// <p>Identifies a specific revision of the <code>$LATEST</code> version.</p>
    /// <p>When you create a new bot alias, leave the <code>checksum</code> field blank. If you specify a checksum you get a <code>BadRequestException</code> exception.</p>
    /// <p>When you want to update a bot alias, set the <code>checksum</code> field to the checksum of the most recent revision of the <code>$LATEST</code> version. If you don't specify the <code> checksum</code> field, or if the checksum does not match the <code>$LATEST</code> version, you get a <code>PreconditionFailedException</code> exception.</p>
    pub checksum: ::std::option::Option<::std::string::String>,
    /// <p>Settings for conversation logs for the alias.</p>
    pub conversation_logs: ::std::option::Option<crate::types::ConversationLogsRequest>,
    /// <p>A list of tags to add to the bot alias. You can only add tags when you create an alias, you can't use the <code>PutBotAlias</code> operation to update the tags on a bot alias. To update tags, use the <code>TagResource</code> operation.</p>
    pub tags: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
}
impl PutBotAliasInput {
    /// <p>The name of the alias. The name is <i>not</i> case sensitive.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>A description of the alias.</p>
    pub fn description(&self) -> ::std::option::Option<&str> {
        self.description.as_deref()
    }
    /// <p>The version of the bot.</p>
    pub fn bot_version(&self) -> ::std::option::Option<&str> {
        self.bot_version.as_deref()
    }
    /// <p>The name of the bot.</p>
    pub fn bot_name(&self) -> ::std::option::Option<&str> {
        self.bot_name.as_deref()
    }
    /// <p>Identifies a specific revision of the <code>$LATEST</code> version.</p>
    /// <p>When you create a new bot alias, leave the <code>checksum</code> field blank. If you specify a checksum you get a <code>BadRequestException</code> exception.</p>
    /// <p>When you want to update a bot alias, set the <code>checksum</code> field to the checksum of the most recent revision of the <code>$LATEST</code> version. If you don't specify the <code> checksum</code> field, or if the checksum does not match the <code>$LATEST</code> version, you get a <code>PreconditionFailedException</code> exception.</p>
    pub fn checksum(&self) -> ::std::option::Option<&str> {
        self.checksum.as_deref()
    }
    /// <p>Settings for conversation logs for the alias.</p>
    pub fn conversation_logs(&self) -> ::std::option::Option<&crate::types::ConversationLogsRequest> {
        self.conversation_logs.as_ref()
    }
    /// <p>A list of tags to add to the bot alias. You can only add tags when you create an alias, you can't use the <code>PutBotAlias</code> operation to update the tags on a bot alias. To update tags, use the <code>TagResource</code> operation.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.tags.is_none()`.
    pub fn tags(&self) -> &[crate::types::Tag] {
        self.tags.as_deref().unwrap_or_default()
    }
}
impl PutBotAliasInput {
    /// Creates a new builder-style object to manufacture [`PutBotAliasInput`](crate::operation::put_bot_alias::PutBotAliasInput).
    pub fn builder() -> crate::operation::put_bot_alias::builders::PutBotAliasInputBuilder {
        crate::operation::put_bot_alias::builders::PutBotAliasInputBuilder::default()
    }
}

/// A builder for [`PutBotAliasInput`](crate::operation::put_bot_alias::PutBotAliasInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct PutBotAliasInputBuilder {
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) description: ::std::option::Option<::std::string::String>,
    pub(crate) bot_version: ::std::option::Option<::std::string::String>,
    pub(crate) bot_name: ::std::option::Option<::std::string::String>,
    pub(crate) checksum: ::std::option::Option<::std::string::String>,
    pub(crate) conversation_logs: ::std::option::Option<crate::types::ConversationLogsRequest>,
    pub(crate) tags: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
}
impl PutBotAliasInputBuilder {
    /// <p>The name of the alias. The name is <i>not</i> case sensitive.</p>
    /// This field is required.
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the alias. The name is <i>not</i> case sensitive.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the alias. The name is <i>not</i> case sensitive.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>A description of the alias.</p>
    pub fn description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A description of the alias.</p>
    pub fn set_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.description = input;
        self
    }
    /// <p>A description of the alias.</p>
    pub fn get_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.description
    }
    /// <p>The version of the bot.</p>
    /// This field is required.
    pub fn bot_version(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.bot_version = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The version of the bot.</p>
    pub fn set_bot_version(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.bot_version = input;
        self
    }
    /// <p>The version of the bot.</p>
    pub fn get_bot_version(&self) -> &::std::option::Option<::std::string::String> {
        &self.bot_version
    }
    /// <p>The name of the bot.</p>
    /// This field is required.
    pub fn bot_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.bot_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the bot.</p>
    pub fn set_bot_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.bot_name = input;
        self
    }
    /// <p>The name of the bot.</p>
    pub fn get_bot_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.bot_name
    }
    /// <p>Identifies a specific revision of the <code>$LATEST</code> version.</p>
    /// <p>When you create a new bot alias, leave the <code>checksum</code> field blank. If you specify a checksum you get a <code>BadRequestException</code> exception.</p>
    /// <p>When you want to update a bot alias, set the <code>checksum</code> field to the checksum of the most recent revision of the <code>$LATEST</code> version. If you don't specify the <code> checksum</code> field, or if the checksum does not match the <code>$LATEST</code> version, you get a <code>PreconditionFailedException</code> exception.</p>
    pub fn checksum(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.checksum = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Identifies a specific revision of the <code>$LATEST</code> version.</p>
    /// <p>When you create a new bot alias, leave the <code>checksum</code> field blank. If you specify a checksum you get a <code>BadRequestException</code> exception.</p>
    /// <p>When you want to update a bot alias, set the <code>checksum</code> field to the checksum of the most recent revision of the <code>$LATEST</code> version. If you don't specify the <code> checksum</code> field, or if the checksum does not match the <code>$LATEST</code> version, you get a <code>PreconditionFailedException</code> exception.</p>
    pub fn set_checksum(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.checksum = input;
        self
    }
    /// <p>Identifies a specific revision of the <code>$LATEST</code> version.</p>
    /// <p>When you create a new bot alias, leave the <code>checksum</code> field blank. If you specify a checksum you get a <code>BadRequestException</code> exception.</p>
    /// <p>When you want to update a bot alias, set the <code>checksum</code> field to the checksum of the most recent revision of the <code>$LATEST</code> version. If you don't specify the <code> checksum</code> field, or if the checksum does not match the <code>$LATEST</code> version, you get a <code>PreconditionFailedException</code> exception.</p>
    pub fn get_checksum(&self) -> &::std::option::Option<::std::string::String> {
        &self.checksum
    }
    /// <p>Settings for conversation logs for the alias.</p>
    pub fn conversation_logs(mut self, input: crate::types::ConversationLogsRequest) -> Self {
        self.conversation_logs = ::std::option::Option::Some(input);
        self
    }
    /// <p>Settings for conversation logs for the alias.</p>
    pub fn set_conversation_logs(mut self, input: ::std::option::Option<crate::types::ConversationLogsRequest>) -> Self {
        self.conversation_logs = input;
        self
    }
    /// <p>Settings for conversation logs for the alias.</p>
    pub fn get_conversation_logs(&self) -> &::std::option::Option<crate::types::ConversationLogsRequest> {
        &self.conversation_logs
    }
    /// Appends an item to `tags`.
    ///
    /// To override the contents of this collection use [`set_tags`](Self::set_tags).
    ///
    /// <p>A list of tags to add to the bot alias. You can only add tags when you create an alias, you can't use the <code>PutBotAlias</code> operation to update the tags on a bot alias. To update tags, use the <code>TagResource</code> operation.</p>
    pub fn tags(mut self, input: crate::types::Tag) -> Self {
        let mut v = self.tags.unwrap_or_default();
        v.push(input);
        self.tags = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of tags to add to the bot alias. You can only add tags when you create an alias, you can't use the <code>PutBotAlias</code> operation to update the tags on a bot alias. To update tags, use the <code>TagResource</code> operation.</p>
    pub fn set_tags(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>) -> Self {
        self.tags = input;
        self
    }
    /// <p>A list of tags to add to the bot alias. You can only add tags when you create an alias, you can't use the <code>PutBotAlias</code> operation to update the tags on a bot alias. To update tags, use the <code>TagResource</code> operation.</p>
    pub fn get_tags(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Tag>> {
        &self.tags
    }
    /// Consumes the builder and constructs a [`PutBotAliasInput`](crate::operation::put_bot_alias::PutBotAliasInput).
    pub fn build(self) -> ::std::result::Result<crate::operation::put_bot_alias::PutBotAliasInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::put_bot_alias::PutBotAliasInput {
            name: self.name,
            description: self.description,
            bot_version: self.bot_version,
            bot_name: self.bot_name,
            checksum: self.checksum,
            conversation_logs: self.conversation_logs,
            tags: self.tags,
        })
    }
}
