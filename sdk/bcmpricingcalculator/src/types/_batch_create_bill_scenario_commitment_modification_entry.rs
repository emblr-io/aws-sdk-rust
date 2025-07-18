// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Represents an entry object in the batch operation to create bill scenario commitment modifications.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct BatchCreateBillScenarioCommitmentModificationEntry {
    /// <p>A unique identifier for this entry in the batch operation. This can be any valid string. This key is useful to identify errors associated with any commitment entry as any error is returned with this key.</p>
    pub key: ::std::string::String,
    /// <p>An optional group identifier for the commitment modification.</p>
    pub group: ::std::option::Option<::std::string::String>,
    /// <p>The Amazon Web Services account ID to which this commitment will be applied to.</p>
    pub usage_account_id: ::std::string::String,
    /// <p>The specific commitment action to be taken (e.g., adding a Reserved Instance or Savings Plan).</p>
    pub commitment_action: ::std::option::Option<crate::types::BillScenarioCommitmentModificationAction>,
}
impl BatchCreateBillScenarioCommitmentModificationEntry {
    /// <p>A unique identifier for this entry in the batch operation. This can be any valid string. This key is useful to identify errors associated with any commitment entry as any error is returned with this key.</p>
    pub fn key(&self) -> &str {
        use std::ops::Deref;
        self.key.deref()
    }
    /// <p>An optional group identifier for the commitment modification.</p>
    pub fn group(&self) -> ::std::option::Option<&str> {
        self.group.as_deref()
    }
    /// <p>The Amazon Web Services account ID to which this commitment will be applied to.</p>
    pub fn usage_account_id(&self) -> &str {
        use std::ops::Deref;
        self.usage_account_id.deref()
    }
    /// <p>The specific commitment action to be taken (e.g., adding a Reserved Instance or Savings Plan).</p>
    pub fn commitment_action(&self) -> ::std::option::Option<&crate::types::BillScenarioCommitmentModificationAction> {
        self.commitment_action.as_ref()
    }
}
impl BatchCreateBillScenarioCommitmentModificationEntry {
    /// Creates a new builder-style object to manufacture [`BatchCreateBillScenarioCommitmentModificationEntry`](crate::types::BatchCreateBillScenarioCommitmentModificationEntry).
    pub fn builder() -> crate::types::builders::BatchCreateBillScenarioCommitmentModificationEntryBuilder {
        crate::types::builders::BatchCreateBillScenarioCommitmentModificationEntryBuilder::default()
    }
}

/// A builder for [`BatchCreateBillScenarioCommitmentModificationEntry`](crate::types::BatchCreateBillScenarioCommitmentModificationEntry).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct BatchCreateBillScenarioCommitmentModificationEntryBuilder {
    pub(crate) key: ::std::option::Option<::std::string::String>,
    pub(crate) group: ::std::option::Option<::std::string::String>,
    pub(crate) usage_account_id: ::std::option::Option<::std::string::String>,
    pub(crate) commitment_action: ::std::option::Option<crate::types::BillScenarioCommitmentModificationAction>,
}
impl BatchCreateBillScenarioCommitmentModificationEntryBuilder {
    /// <p>A unique identifier for this entry in the batch operation. This can be any valid string. This key is useful to identify errors associated with any commitment entry as any error is returned with this key.</p>
    /// This field is required.
    pub fn key(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.key = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A unique identifier for this entry in the batch operation. This can be any valid string. This key is useful to identify errors associated with any commitment entry as any error is returned with this key.</p>
    pub fn set_key(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.key = input;
        self
    }
    /// <p>A unique identifier for this entry in the batch operation. This can be any valid string. This key is useful to identify errors associated with any commitment entry as any error is returned with this key.</p>
    pub fn get_key(&self) -> &::std::option::Option<::std::string::String> {
        &self.key
    }
    /// <p>An optional group identifier for the commitment modification.</p>
    pub fn group(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.group = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>An optional group identifier for the commitment modification.</p>
    pub fn set_group(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.group = input;
        self
    }
    /// <p>An optional group identifier for the commitment modification.</p>
    pub fn get_group(&self) -> &::std::option::Option<::std::string::String> {
        &self.group
    }
    /// <p>The Amazon Web Services account ID to which this commitment will be applied to.</p>
    /// This field is required.
    pub fn usage_account_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.usage_account_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Web Services account ID to which this commitment will be applied to.</p>
    pub fn set_usage_account_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.usage_account_id = input;
        self
    }
    /// <p>The Amazon Web Services account ID to which this commitment will be applied to.</p>
    pub fn get_usage_account_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.usage_account_id
    }
    /// <p>The specific commitment action to be taken (e.g., adding a Reserved Instance or Savings Plan).</p>
    /// This field is required.
    pub fn commitment_action(mut self, input: crate::types::BillScenarioCommitmentModificationAction) -> Self {
        self.commitment_action = ::std::option::Option::Some(input);
        self
    }
    /// <p>The specific commitment action to be taken (e.g., adding a Reserved Instance or Savings Plan).</p>
    pub fn set_commitment_action(mut self, input: ::std::option::Option<crate::types::BillScenarioCommitmentModificationAction>) -> Self {
        self.commitment_action = input;
        self
    }
    /// <p>The specific commitment action to be taken (e.g., adding a Reserved Instance or Savings Plan).</p>
    pub fn get_commitment_action(&self) -> &::std::option::Option<crate::types::BillScenarioCommitmentModificationAction> {
        &self.commitment_action
    }
    /// Consumes the builder and constructs a [`BatchCreateBillScenarioCommitmentModificationEntry`](crate::types::BatchCreateBillScenarioCommitmentModificationEntry).
    /// This method will fail if any of the following fields are not set:
    /// - [`key`](crate::types::builders::BatchCreateBillScenarioCommitmentModificationEntryBuilder::key)
    /// - [`usage_account_id`](crate::types::builders::BatchCreateBillScenarioCommitmentModificationEntryBuilder::usage_account_id)
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::types::BatchCreateBillScenarioCommitmentModificationEntry, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::types::BatchCreateBillScenarioCommitmentModificationEntry {
            key: self.key.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "key",
                    "key was not specified but it is required when building BatchCreateBillScenarioCommitmentModificationEntry",
                )
            })?,
            group: self.group,
            usage_account_id: self.usage_account_id.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "usage_account_id",
                    "usage_account_id was not specified but it is required when building BatchCreateBillScenarioCommitmentModificationEntry",
                )
            })?,
            commitment_action: self.commitment_action,
        })
    }
}
