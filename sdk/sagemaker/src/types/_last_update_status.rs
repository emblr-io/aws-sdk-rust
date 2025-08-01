// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A value that indicates whether the update was successful.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct LastUpdateStatus {
    /// <p>A value that indicates whether the update was made successful.</p>
    pub status: ::std::option::Option<crate::types::LastUpdateStatusValue>,
    /// <p>If the update wasn't successful, indicates the reason why it failed.</p>
    pub failure_reason: ::std::option::Option<::std::string::String>,
}
impl LastUpdateStatus {
    /// <p>A value that indicates whether the update was made successful.</p>
    pub fn status(&self) -> ::std::option::Option<&crate::types::LastUpdateStatusValue> {
        self.status.as_ref()
    }
    /// <p>If the update wasn't successful, indicates the reason why it failed.</p>
    pub fn failure_reason(&self) -> ::std::option::Option<&str> {
        self.failure_reason.as_deref()
    }
}
impl LastUpdateStatus {
    /// Creates a new builder-style object to manufacture [`LastUpdateStatus`](crate::types::LastUpdateStatus).
    pub fn builder() -> crate::types::builders::LastUpdateStatusBuilder {
        crate::types::builders::LastUpdateStatusBuilder::default()
    }
}

/// A builder for [`LastUpdateStatus`](crate::types::LastUpdateStatus).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct LastUpdateStatusBuilder {
    pub(crate) status: ::std::option::Option<crate::types::LastUpdateStatusValue>,
    pub(crate) failure_reason: ::std::option::Option<::std::string::String>,
}
impl LastUpdateStatusBuilder {
    /// <p>A value that indicates whether the update was made successful.</p>
    /// This field is required.
    pub fn status(mut self, input: crate::types::LastUpdateStatusValue) -> Self {
        self.status = ::std::option::Option::Some(input);
        self
    }
    /// <p>A value that indicates whether the update was made successful.</p>
    pub fn set_status(mut self, input: ::std::option::Option<crate::types::LastUpdateStatusValue>) -> Self {
        self.status = input;
        self
    }
    /// <p>A value that indicates whether the update was made successful.</p>
    pub fn get_status(&self) -> &::std::option::Option<crate::types::LastUpdateStatusValue> {
        &self.status
    }
    /// <p>If the update wasn't successful, indicates the reason why it failed.</p>
    pub fn failure_reason(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.failure_reason = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>If the update wasn't successful, indicates the reason why it failed.</p>
    pub fn set_failure_reason(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.failure_reason = input;
        self
    }
    /// <p>If the update wasn't successful, indicates the reason why it failed.</p>
    pub fn get_failure_reason(&self) -> &::std::option::Option<::std::string::String> {
        &self.failure_reason
    }
    /// Consumes the builder and constructs a [`LastUpdateStatus`](crate::types::LastUpdateStatus).
    pub fn build(self) -> crate::types::LastUpdateStatus {
        crate::types::LastUpdateStatus {
            status: self.status,
            failure_reason: self.failure_reason,
        }
    }
}
