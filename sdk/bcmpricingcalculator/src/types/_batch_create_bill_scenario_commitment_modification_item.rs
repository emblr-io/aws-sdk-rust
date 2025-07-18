// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Represents a successfully created item in a batch operation for bill scenario commitment modifications.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct BatchCreateBillScenarioCommitmentModificationItem {
    /// <p>The key of the successfully created entry. This can be any valid string. This key is useful to identify errors associated with any commitment entry as any error is returned with this key.</p>
    pub key: ::std::option::Option<::std::string::String>,
    /// <p>The unique identifier assigned to the created commitment modification.</p>
    pub id: ::std::option::Option<::std::string::String>,
    /// <p>The group identifier for the created commitment modification.</p>
    pub group: ::std::option::Option<::std::string::String>,
    /// <p>The Amazon Web Services account ID associated with the created commitment modification.</p>
    pub usage_account_id: ::std::option::Option<::std::string::String>,
    /// <p>The specific commitment action that was taken.</p>
    pub commitment_action: ::std::option::Option<crate::types::BillScenarioCommitmentModificationAction>,
}
impl BatchCreateBillScenarioCommitmentModificationItem {
    /// <p>The key of the successfully created entry. This can be any valid string. This key is useful to identify errors associated with any commitment entry as any error is returned with this key.</p>
    pub fn key(&self) -> ::std::option::Option<&str> {
        self.key.as_deref()
    }
    /// <p>The unique identifier assigned to the created commitment modification.</p>
    pub fn id(&self) -> ::std::option::Option<&str> {
        self.id.as_deref()
    }
    /// <p>The group identifier for the created commitment modification.</p>
    pub fn group(&self) -> ::std::option::Option<&str> {
        self.group.as_deref()
    }
    /// <p>The Amazon Web Services account ID associated with the created commitment modification.</p>
    pub fn usage_account_id(&self) -> ::std::option::Option<&str> {
        self.usage_account_id.as_deref()
    }
    /// <p>The specific commitment action that was taken.</p>
    pub fn commitment_action(&self) -> ::std::option::Option<&crate::types::BillScenarioCommitmentModificationAction> {
        self.commitment_action.as_ref()
    }
}
impl BatchCreateBillScenarioCommitmentModificationItem {
    /// Creates a new builder-style object to manufacture [`BatchCreateBillScenarioCommitmentModificationItem`](crate::types::BatchCreateBillScenarioCommitmentModificationItem).
    pub fn builder() -> crate::types::builders::BatchCreateBillScenarioCommitmentModificationItemBuilder {
        crate::types::builders::BatchCreateBillScenarioCommitmentModificationItemBuilder::default()
    }
}

/// A builder for [`BatchCreateBillScenarioCommitmentModificationItem`](crate::types::BatchCreateBillScenarioCommitmentModificationItem).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct BatchCreateBillScenarioCommitmentModificationItemBuilder {
    pub(crate) key: ::std::option::Option<::std::string::String>,
    pub(crate) id: ::std::option::Option<::std::string::String>,
    pub(crate) group: ::std::option::Option<::std::string::String>,
    pub(crate) usage_account_id: ::std::option::Option<::std::string::String>,
    pub(crate) commitment_action: ::std::option::Option<crate::types::BillScenarioCommitmentModificationAction>,
}
impl BatchCreateBillScenarioCommitmentModificationItemBuilder {
    /// <p>The key of the successfully created entry. This can be any valid string. This key is useful to identify errors associated with any commitment entry as any error is returned with this key.</p>
    pub fn key(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.key = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The key of the successfully created entry. This can be any valid string. This key is useful to identify errors associated with any commitment entry as any error is returned with this key.</p>
    pub fn set_key(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.key = input;
        self
    }
    /// <p>The key of the successfully created entry. This can be any valid string. This key is useful to identify errors associated with any commitment entry as any error is returned with this key.</p>
    pub fn get_key(&self) -> &::std::option::Option<::std::string::String> {
        &self.key
    }
    /// <p>The unique identifier assigned to the created commitment modification.</p>
    pub fn id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique identifier assigned to the created commitment modification.</p>
    pub fn set_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.id = input;
        self
    }
    /// <p>The unique identifier assigned to the created commitment modification.</p>
    pub fn get_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.id
    }
    /// <p>The group identifier for the created commitment modification.</p>
    pub fn group(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.group = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The group identifier for the created commitment modification.</p>
    pub fn set_group(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.group = input;
        self
    }
    /// <p>The group identifier for the created commitment modification.</p>
    pub fn get_group(&self) -> &::std::option::Option<::std::string::String> {
        &self.group
    }
    /// <p>The Amazon Web Services account ID associated with the created commitment modification.</p>
    pub fn usage_account_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.usage_account_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Web Services account ID associated with the created commitment modification.</p>
    pub fn set_usage_account_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.usage_account_id = input;
        self
    }
    /// <p>The Amazon Web Services account ID associated with the created commitment modification.</p>
    pub fn get_usage_account_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.usage_account_id
    }
    /// <p>The specific commitment action that was taken.</p>
    pub fn commitment_action(mut self, input: crate::types::BillScenarioCommitmentModificationAction) -> Self {
        self.commitment_action = ::std::option::Option::Some(input);
        self
    }
    /// <p>The specific commitment action that was taken.</p>
    pub fn set_commitment_action(mut self, input: ::std::option::Option<crate::types::BillScenarioCommitmentModificationAction>) -> Self {
        self.commitment_action = input;
        self
    }
    /// <p>The specific commitment action that was taken.</p>
    pub fn get_commitment_action(&self) -> &::std::option::Option<crate::types::BillScenarioCommitmentModificationAction> {
        &self.commitment_action
    }
    /// Consumes the builder and constructs a [`BatchCreateBillScenarioCommitmentModificationItem`](crate::types::BatchCreateBillScenarioCommitmentModificationItem).
    pub fn build(self) -> crate::types::BatchCreateBillScenarioCommitmentModificationItem {
        crate::types::BatchCreateBillScenarioCommitmentModificationItem {
            key: self.key,
            id: self.id,
            group: self.group,
            usage_account_id: self.usage_account_id,
            commitment_action: self.commitment_action,
        }
    }
}
