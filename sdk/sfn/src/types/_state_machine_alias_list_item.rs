// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Contains details about a specific state machine alias.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct StateMachineAliasListItem {
    /// <p>The Amazon Resource Name (ARN) that identifies a state machine alias. The alias ARN is a combination of state machine ARN and the alias name separated by a colon (:). For example, <code>stateMachineARN:PROD</code>.</p>
    pub state_machine_alias_arn: ::std::string::String,
    /// <p>The creation date of a state machine alias.</p>
    pub creation_date: ::aws_smithy_types::DateTime,
}
impl StateMachineAliasListItem {
    /// <p>The Amazon Resource Name (ARN) that identifies a state machine alias. The alias ARN is a combination of state machine ARN and the alias name separated by a colon (:). For example, <code>stateMachineARN:PROD</code>.</p>
    pub fn state_machine_alias_arn(&self) -> &str {
        use std::ops::Deref;
        self.state_machine_alias_arn.deref()
    }
    /// <p>The creation date of a state machine alias.</p>
    pub fn creation_date(&self) -> &::aws_smithy_types::DateTime {
        &self.creation_date
    }
}
impl StateMachineAliasListItem {
    /// Creates a new builder-style object to manufacture [`StateMachineAliasListItem`](crate::types::StateMachineAliasListItem).
    pub fn builder() -> crate::types::builders::StateMachineAliasListItemBuilder {
        crate::types::builders::StateMachineAliasListItemBuilder::default()
    }
}

/// A builder for [`StateMachineAliasListItem`](crate::types::StateMachineAliasListItem).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct StateMachineAliasListItemBuilder {
    pub(crate) state_machine_alias_arn: ::std::option::Option<::std::string::String>,
    pub(crate) creation_date: ::std::option::Option<::aws_smithy_types::DateTime>,
}
impl StateMachineAliasListItemBuilder {
    /// <p>The Amazon Resource Name (ARN) that identifies a state machine alias. The alias ARN is a combination of state machine ARN and the alias name separated by a colon (:). For example, <code>stateMachineARN:PROD</code>.</p>
    /// This field is required.
    pub fn state_machine_alias_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.state_machine_alias_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) that identifies a state machine alias. The alias ARN is a combination of state machine ARN and the alias name separated by a colon (:). For example, <code>stateMachineARN:PROD</code>.</p>
    pub fn set_state_machine_alias_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.state_machine_alias_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) that identifies a state machine alias. The alias ARN is a combination of state machine ARN and the alias name separated by a colon (:). For example, <code>stateMachineARN:PROD</code>.</p>
    pub fn get_state_machine_alias_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.state_machine_alias_arn
    }
    /// <p>The creation date of a state machine alias.</p>
    /// This field is required.
    pub fn creation_date(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.creation_date = ::std::option::Option::Some(input);
        self
    }
    /// <p>The creation date of a state machine alias.</p>
    pub fn set_creation_date(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.creation_date = input;
        self
    }
    /// <p>The creation date of a state machine alias.</p>
    pub fn get_creation_date(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.creation_date
    }
    /// Consumes the builder and constructs a [`StateMachineAliasListItem`](crate::types::StateMachineAliasListItem).
    /// This method will fail if any of the following fields are not set:
    /// - [`state_machine_alias_arn`](crate::types::builders::StateMachineAliasListItemBuilder::state_machine_alias_arn)
    /// - [`creation_date`](crate::types::builders::StateMachineAliasListItemBuilder::creation_date)
    pub fn build(self) -> ::std::result::Result<crate::types::StateMachineAliasListItem, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::StateMachineAliasListItem {
            state_machine_alias_arn: self.state_machine_alias_arn.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "state_machine_alias_arn",
                    "state_machine_alias_arn was not specified but it is required when building StateMachineAliasListItem",
                )
            })?,
            creation_date: self.creation_date.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "creation_date",
                    "creation_date was not specified but it is required when building StateMachineAliasListItem",
                )
            })?,
        })
    }
}
