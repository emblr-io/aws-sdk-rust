// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteBotAliasInput {
    /// <p>The name of the alias to delete. The name is case sensitive.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>The name of the bot that the alias points to.</p>
    pub bot_name: ::std::option::Option<::std::string::String>,
}
impl DeleteBotAliasInput {
    /// <p>The name of the alias to delete. The name is case sensitive.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>The name of the bot that the alias points to.</p>
    pub fn bot_name(&self) -> ::std::option::Option<&str> {
        self.bot_name.as_deref()
    }
}
impl DeleteBotAliasInput {
    /// Creates a new builder-style object to manufacture [`DeleteBotAliasInput`](crate::operation::delete_bot_alias::DeleteBotAliasInput).
    pub fn builder() -> crate::operation::delete_bot_alias::builders::DeleteBotAliasInputBuilder {
        crate::operation::delete_bot_alias::builders::DeleteBotAliasInputBuilder::default()
    }
}

/// A builder for [`DeleteBotAliasInput`](crate::operation::delete_bot_alias::DeleteBotAliasInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeleteBotAliasInputBuilder {
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) bot_name: ::std::option::Option<::std::string::String>,
}
impl DeleteBotAliasInputBuilder {
    /// <p>The name of the alias to delete. The name is case sensitive.</p>
    /// This field is required.
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the alias to delete. The name is case sensitive.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the alias to delete. The name is case sensitive.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>The name of the bot that the alias points to.</p>
    /// This field is required.
    pub fn bot_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.bot_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the bot that the alias points to.</p>
    pub fn set_bot_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.bot_name = input;
        self
    }
    /// <p>The name of the bot that the alias points to.</p>
    pub fn get_bot_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.bot_name
    }
    /// Consumes the builder and constructs a [`DeleteBotAliasInput`](crate::operation::delete_bot_alias::DeleteBotAliasInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::delete_bot_alias::DeleteBotAliasInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::delete_bot_alias::DeleteBotAliasInput {
            name: self.name,
            bot_name: self.bot_name,
        })
    }
}
