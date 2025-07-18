// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The cost allocation tag backfill request structure that contains metadata and details of a certain backfill.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CostAllocationTagBackfillRequest {
    /// <p>The date the backfill starts from.</p>
    pub backfill_from: ::std::option::Option<::std::string::String>,
    /// <p>The time when the backfill was requested.</p>
    pub requested_at: ::std::option::Option<::std::string::String>,
    /// <p>The backfill completion time.</p>
    pub completed_at: ::std::option::Option<::std::string::String>,
    /// <p>The status of the cost allocation tag backfill request.</p>
    pub backfill_status: ::std::option::Option<crate::types::CostAllocationTagBackfillStatus>,
    /// <p>The time when the backfill status was last updated.</p>
    pub last_updated_at: ::std::option::Option<::std::string::String>,
}
impl CostAllocationTagBackfillRequest {
    /// <p>The date the backfill starts from.</p>
    pub fn backfill_from(&self) -> ::std::option::Option<&str> {
        self.backfill_from.as_deref()
    }
    /// <p>The time when the backfill was requested.</p>
    pub fn requested_at(&self) -> ::std::option::Option<&str> {
        self.requested_at.as_deref()
    }
    /// <p>The backfill completion time.</p>
    pub fn completed_at(&self) -> ::std::option::Option<&str> {
        self.completed_at.as_deref()
    }
    /// <p>The status of the cost allocation tag backfill request.</p>
    pub fn backfill_status(&self) -> ::std::option::Option<&crate::types::CostAllocationTagBackfillStatus> {
        self.backfill_status.as_ref()
    }
    /// <p>The time when the backfill status was last updated.</p>
    pub fn last_updated_at(&self) -> ::std::option::Option<&str> {
        self.last_updated_at.as_deref()
    }
}
impl CostAllocationTagBackfillRequest {
    /// Creates a new builder-style object to manufacture [`CostAllocationTagBackfillRequest`](crate::types::CostAllocationTagBackfillRequest).
    pub fn builder() -> crate::types::builders::CostAllocationTagBackfillRequestBuilder {
        crate::types::builders::CostAllocationTagBackfillRequestBuilder::default()
    }
}

/// A builder for [`CostAllocationTagBackfillRequest`](crate::types::CostAllocationTagBackfillRequest).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CostAllocationTagBackfillRequestBuilder {
    pub(crate) backfill_from: ::std::option::Option<::std::string::String>,
    pub(crate) requested_at: ::std::option::Option<::std::string::String>,
    pub(crate) completed_at: ::std::option::Option<::std::string::String>,
    pub(crate) backfill_status: ::std::option::Option<crate::types::CostAllocationTagBackfillStatus>,
    pub(crate) last_updated_at: ::std::option::Option<::std::string::String>,
}
impl CostAllocationTagBackfillRequestBuilder {
    /// <p>The date the backfill starts from.</p>
    pub fn backfill_from(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.backfill_from = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The date the backfill starts from.</p>
    pub fn set_backfill_from(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.backfill_from = input;
        self
    }
    /// <p>The date the backfill starts from.</p>
    pub fn get_backfill_from(&self) -> &::std::option::Option<::std::string::String> {
        &self.backfill_from
    }
    /// <p>The time when the backfill was requested.</p>
    pub fn requested_at(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.requested_at = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The time when the backfill was requested.</p>
    pub fn set_requested_at(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.requested_at = input;
        self
    }
    /// <p>The time when the backfill was requested.</p>
    pub fn get_requested_at(&self) -> &::std::option::Option<::std::string::String> {
        &self.requested_at
    }
    /// <p>The backfill completion time.</p>
    pub fn completed_at(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.completed_at = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The backfill completion time.</p>
    pub fn set_completed_at(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.completed_at = input;
        self
    }
    /// <p>The backfill completion time.</p>
    pub fn get_completed_at(&self) -> &::std::option::Option<::std::string::String> {
        &self.completed_at
    }
    /// <p>The status of the cost allocation tag backfill request.</p>
    pub fn backfill_status(mut self, input: crate::types::CostAllocationTagBackfillStatus) -> Self {
        self.backfill_status = ::std::option::Option::Some(input);
        self
    }
    /// <p>The status of the cost allocation tag backfill request.</p>
    pub fn set_backfill_status(mut self, input: ::std::option::Option<crate::types::CostAllocationTagBackfillStatus>) -> Self {
        self.backfill_status = input;
        self
    }
    /// <p>The status of the cost allocation tag backfill request.</p>
    pub fn get_backfill_status(&self) -> &::std::option::Option<crate::types::CostAllocationTagBackfillStatus> {
        &self.backfill_status
    }
    /// <p>The time when the backfill status was last updated.</p>
    pub fn last_updated_at(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.last_updated_at = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The time when the backfill status was last updated.</p>
    pub fn set_last_updated_at(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.last_updated_at = input;
        self
    }
    /// <p>The time when the backfill status was last updated.</p>
    pub fn get_last_updated_at(&self) -> &::std::option::Option<::std::string::String> {
        &self.last_updated_at
    }
    /// Consumes the builder and constructs a [`CostAllocationTagBackfillRequest`](crate::types::CostAllocationTagBackfillRequest).
    pub fn build(self) -> crate::types::CostAllocationTagBackfillRequest {
        crate::types::CostAllocationTagBackfillRequest {
            backfill_from: self.backfill_from,
            requested_at: self.requested_at,
            completed_at: self.completed_at,
            backfill_status: self.backfill_status,
            last_updated_at: self.last_updated_at,
        }
    }
}
