// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Configuration object that contains the most recent account settings update, visible only if settings have been updated previously.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct LastUpdate {
    /// <p>The number of TimeStream Compute Units (TCUs) requested in the last account settings update.</p>
    pub target_query_tcu: ::std::option::Option<i32>,
    /// <p>The status of the last update. Can be either <code>PENDING</code>, <code>FAILED</code>, or <code>SUCCEEDED</code>.</p>
    pub status: ::std::option::Option<crate::types::LastUpdateStatus>,
    /// <p>Error message describing the last account settings update status, visible only if an error occurred.</p>
    pub status_message: ::std::option::Option<::std::string::String>,
}
impl LastUpdate {
    /// <p>The number of TimeStream Compute Units (TCUs) requested in the last account settings update.</p>
    pub fn target_query_tcu(&self) -> ::std::option::Option<i32> {
        self.target_query_tcu
    }
    /// <p>The status of the last update. Can be either <code>PENDING</code>, <code>FAILED</code>, or <code>SUCCEEDED</code>.</p>
    pub fn status(&self) -> ::std::option::Option<&crate::types::LastUpdateStatus> {
        self.status.as_ref()
    }
    /// <p>Error message describing the last account settings update status, visible only if an error occurred.</p>
    pub fn status_message(&self) -> ::std::option::Option<&str> {
        self.status_message.as_deref()
    }
}
impl LastUpdate {
    /// Creates a new builder-style object to manufacture [`LastUpdate`](crate::types::LastUpdate).
    pub fn builder() -> crate::types::builders::LastUpdateBuilder {
        crate::types::builders::LastUpdateBuilder::default()
    }
}

/// A builder for [`LastUpdate`](crate::types::LastUpdate).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct LastUpdateBuilder {
    pub(crate) target_query_tcu: ::std::option::Option<i32>,
    pub(crate) status: ::std::option::Option<crate::types::LastUpdateStatus>,
    pub(crate) status_message: ::std::option::Option<::std::string::String>,
}
impl LastUpdateBuilder {
    /// <p>The number of TimeStream Compute Units (TCUs) requested in the last account settings update.</p>
    pub fn target_query_tcu(mut self, input: i32) -> Self {
        self.target_query_tcu = ::std::option::Option::Some(input);
        self
    }
    /// <p>The number of TimeStream Compute Units (TCUs) requested in the last account settings update.</p>
    pub fn set_target_query_tcu(mut self, input: ::std::option::Option<i32>) -> Self {
        self.target_query_tcu = input;
        self
    }
    /// <p>The number of TimeStream Compute Units (TCUs) requested in the last account settings update.</p>
    pub fn get_target_query_tcu(&self) -> &::std::option::Option<i32> {
        &self.target_query_tcu
    }
    /// <p>The status of the last update. Can be either <code>PENDING</code>, <code>FAILED</code>, or <code>SUCCEEDED</code>.</p>
    pub fn status(mut self, input: crate::types::LastUpdateStatus) -> Self {
        self.status = ::std::option::Option::Some(input);
        self
    }
    /// <p>The status of the last update. Can be either <code>PENDING</code>, <code>FAILED</code>, or <code>SUCCEEDED</code>.</p>
    pub fn set_status(mut self, input: ::std::option::Option<crate::types::LastUpdateStatus>) -> Self {
        self.status = input;
        self
    }
    /// <p>The status of the last update. Can be either <code>PENDING</code>, <code>FAILED</code>, or <code>SUCCEEDED</code>.</p>
    pub fn get_status(&self) -> &::std::option::Option<crate::types::LastUpdateStatus> {
        &self.status
    }
    /// <p>Error message describing the last account settings update status, visible only if an error occurred.</p>
    pub fn status_message(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.status_message = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Error message describing the last account settings update status, visible only if an error occurred.</p>
    pub fn set_status_message(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.status_message = input;
        self
    }
    /// <p>Error message describing the last account settings update status, visible only if an error occurred.</p>
    pub fn get_status_message(&self) -> &::std::option::Option<::std::string::String> {
        &self.status_message
    }
    /// Consumes the builder and constructs a [`LastUpdate`](crate::types::LastUpdate).
    pub fn build(self) -> crate::types::LastUpdate {
        crate::types::LastUpdate {
            target_query_tcu: self.target_query_tcu,
            status: self.status,
            status_message: self.status_message,
        }
    }
}
