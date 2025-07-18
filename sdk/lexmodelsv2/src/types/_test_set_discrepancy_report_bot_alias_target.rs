// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Contains information about the bot alias used for the test set discrepancy report.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct TestSetDiscrepancyReportBotAliasTarget {
    /// <p>The unique identifier for the bot alias.</p>
    pub bot_id: ::std::string::String,
    /// <p>The unique identifier for the bot associated with the bot alias.</p>
    pub bot_alias_id: ::std::string::String,
    /// <p>The unique identifier of the locale associated with the bot alias.</p>
    pub locale_id: ::std::string::String,
}
impl TestSetDiscrepancyReportBotAliasTarget {
    /// <p>The unique identifier for the bot alias.</p>
    pub fn bot_id(&self) -> &str {
        use std::ops::Deref;
        self.bot_id.deref()
    }
    /// <p>The unique identifier for the bot associated with the bot alias.</p>
    pub fn bot_alias_id(&self) -> &str {
        use std::ops::Deref;
        self.bot_alias_id.deref()
    }
    /// <p>The unique identifier of the locale associated with the bot alias.</p>
    pub fn locale_id(&self) -> &str {
        use std::ops::Deref;
        self.locale_id.deref()
    }
}
impl TestSetDiscrepancyReportBotAliasTarget {
    /// Creates a new builder-style object to manufacture [`TestSetDiscrepancyReportBotAliasTarget`](crate::types::TestSetDiscrepancyReportBotAliasTarget).
    pub fn builder() -> crate::types::builders::TestSetDiscrepancyReportBotAliasTargetBuilder {
        crate::types::builders::TestSetDiscrepancyReportBotAliasTargetBuilder::default()
    }
}

/// A builder for [`TestSetDiscrepancyReportBotAliasTarget`](crate::types::TestSetDiscrepancyReportBotAliasTarget).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct TestSetDiscrepancyReportBotAliasTargetBuilder {
    pub(crate) bot_id: ::std::option::Option<::std::string::String>,
    pub(crate) bot_alias_id: ::std::option::Option<::std::string::String>,
    pub(crate) locale_id: ::std::option::Option<::std::string::String>,
}
impl TestSetDiscrepancyReportBotAliasTargetBuilder {
    /// <p>The unique identifier for the bot alias.</p>
    /// This field is required.
    pub fn bot_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.bot_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique identifier for the bot alias.</p>
    pub fn set_bot_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.bot_id = input;
        self
    }
    /// <p>The unique identifier for the bot alias.</p>
    pub fn get_bot_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.bot_id
    }
    /// <p>The unique identifier for the bot associated with the bot alias.</p>
    /// This field is required.
    pub fn bot_alias_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.bot_alias_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique identifier for the bot associated with the bot alias.</p>
    pub fn set_bot_alias_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.bot_alias_id = input;
        self
    }
    /// <p>The unique identifier for the bot associated with the bot alias.</p>
    pub fn get_bot_alias_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.bot_alias_id
    }
    /// <p>The unique identifier of the locale associated with the bot alias.</p>
    /// This field is required.
    pub fn locale_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.locale_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique identifier of the locale associated with the bot alias.</p>
    pub fn set_locale_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.locale_id = input;
        self
    }
    /// <p>The unique identifier of the locale associated with the bot alias.</p>
    pub fn get_locale_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.locale_id
    }
    /// Consumes the builder and constructs a [`TestSetDiscrepancyReportBotAliasTarget`](crate::types::TestSetDiscrepancyReportBotAliasTarget).
    /// This method will fail if any of the following fields are not set:
    /// - [`bot_id`](crate::types::builders::TestSetDiscrepancyReportBotAliasTargetBuilder::bot_id)
    /// - [`bot_alias_id`](crate::types::builders::TestSetDiscrepancyReportBotAliasTargetBuilder::bot_alias_id)
    /// - [`locale_id`](crate::types::builders::TestSetDiscrepancyReportBotAliasTargetBuilder::locale_id)
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::types::TestSetDiscrepancyReportBotAliasTarget, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::TestSetDiscrepancyReportBotAliasTarget {
            bot_id: self.bot_id.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "bot_id",
                    "bot_id was not specified but it is required when building TestSetDiscrepancyReportBotAliasTarget",
                )
            })?,
            bot_alias_id: self.bot_alias_id.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "bot_alias_id",
                    "bot_alias_id was not specified but it is required when building TestSetDiscrepancyReportBotAliasTarget",
                )
            })?,
            locale_id: self.locale_id.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "locale_id",
                    "locale_id was not specified but it is required when building TestSetDiscrepancyReportBotAliasTarget",
                )
            })?,
        })
    }
}
