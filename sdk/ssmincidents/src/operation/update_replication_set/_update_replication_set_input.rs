// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UpdateReplicationSetInput {
    /// <p>The Amazon Resource Name (ARN) of the replication set you're updating.</p>
    pub arn: ::std::option::Option<::std::string::String>,
    /// <p>An action to add or delete a Region.</p>
    pub actions: ::std::option::Option<::std::vec::Vec<crate::types::UpdateReplicationSetAction>>,
    /// <p>A token that ensures that the operation is called only once with the specified details.</p>
    pub client_token: ::std::option::Option<::std::string::String>,
}
impl UpdateReplicationSetInput {
    /// <p>The Amazon Resource Name (ARN) of the replication set you're updating.</p>
    pub fn arn(&self) -> ::std::option::Option<&str> {
        self.arn.as_deref()
    }
    /// <p>An action to add or delete a Region.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.actions.is_none()`.
    pub fn actions(&self) -> &[crate::types::UpdateReplicationSetAction] {
        self.actions.as_deref().unwrap_or_default()
    }
    /// <p>A token that ensures that the operation is called only once with the specified details.</p>
    pub fn client_token(&self) -> ::std::option::Option<&str> {
        self.client_token.as_deref()
    }
}
impl UpdateReplicationSetInput {
    /// Creates a new builder-style object to manufacture [`UpdateReplicationSetInput`](crate::operation::update_replication_set::UpdateReplicationSetInput).
    pub fn builder() -> crate::operation::update_replication_set::builders::UpdateReplicationSetInputBuilder {
        crate::operation::update_replication_set::builders::UpdateReplicationSetInputBuilder::default()
    }
}

/// A builder for [`UpdateReplicationSetInput`](crate::operation::update_replication_set::UpdateReplicationSetInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UpdateReplicationSetInputBuilder {
    pub(crate) arn: ::std::option::Option<::std::string::String>,
    pub(crate) actions: ::std::option::Option<::std::vec::Vec<crate::types::UpdateReplicationSetAction>>,
    pub(crate) client_token: ::std::option::Option<::std::string::String>,
}
impl UpdateReplicationSetInputBuilder {
    /// <p>The Amazon Resource Name (ARN) of the replication set you're updating.</p>
    /// This field is required.
    pub fn arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the replication set you're updating.</p>
    pub fn set_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the replication set you're updating.</p>
    pub fn get_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.arn
    }
    /// Appends an item to `actions`.
    ///
    /// To override the contents of this collection use [`set_actions`](Self::set_actions).
    ///
    /// <p>An action to add or delete a Region.</p>
    pub fn actions(mut self, input: crate::types::UpdateReplicationSetAction) -> Self {
        let mut v = self.actions.unwrap_or_default();
        v.push(input);
        self.actions = ::std::option::Option::Some(v);
        self
    }
    /// <p>An action to add or delete a Region.</p>
    pub fn set_actions(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::UpdateReplicationSetAction>>) -> Self {
        self.actions = input;
        self
    }
    /// <p>An action to add or delete a Region.</p>
    pub fn get_actions(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::UpdateReplicationSetAction>> {
        &self.actions
    }
    /// <p>A token that ensures that the operation is called only once with the specified details.</p>
    pub fn client_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.client_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A token that ensures that the operation is called only once with the specified details.</p>
    pub fn set_client_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.client_token = input;
        self
    }
    /// <p>A token that ensures that the operation is called only once with the specified details.</p>
    pub fn get_client_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.client_token
    }
    /// Consumes the builder and constructs a [`UpdateReplicationSetInput`](crate::operation::update_replication_set::UpdateReplicationSetInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::update_replication_set::UpdateReplicationSetInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::update_replication_set::UpdateReplicationSetInput {
            arn: self.arn,
            actions: self.actions,
            client_token: self.client_token,
        })
    }
}
