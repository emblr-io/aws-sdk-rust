// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListProfileNotificationsInput {
    /// <p>The ID assigned to the workload. This ID is unique within an Amazon Web Services Region.</p>
    pub workload_id: ::std::option::Option<::std::string::String>,
    /// <p>The token to use to retrieve the next set of results.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    /// <p>The maximum number of results to return for this request.</p>
    pub max_results: ::std::option::Option<i32>,
}
impl ListProfileNotificationsInput {
    /// <p>The ID assigned to the workload. This ID is unique within an Amazon Web Services Region.</p>
    pub fn workload_id(&self) -> ::std::option::Option<&str> {
        self.workload_id.as_deref()
    }
    /// <p>The token to use to retrieve the next set of results.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
    /// <p>The maximum number of results to return for this request.</p>
    pub fn max_results(&self) -> ::std::option::Option<i32> {
        self.max_results
    }
}
impl ListProfileNotificationsInput {
    /// Creates a new builder-style object to manufacture [`ListProfileNotificationsInput`](crate::operation::list_profile_notifications::ListProfileNotificationsInput).
    pub fn builder() -> crate::operation::list_profile_notifications::builders::ListProfileNotificationsInputBuilder {
        crate::operation::list_profile_notifications::builders::ListProfileNotificationsInputBuilder::default()
    }
}

/// A builder for [`ListProfileNotificationsInput`](crate::operation::list_profile_notifications::ListProfileNotificationsInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListProfileNotificationsInputBuilder {
    pub(crate) workload_id: ::std::option::Option<::std::string::String>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    pub(crate) max_results: ::std::option::Option<i32>,
}
impl ListProfileNotificationsInputBuilder {
    /// <p>The ID assigned to the workload. This ID is unique within an Amazon Web Services Region.</p>
    pub fn workload_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.workload_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID assigned to the workload. This ID is unique within an Amazon Web Services Region.</p>
    pub fn set_workload_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.workload_id = input;
        self
    }
    /// <p>The ID assigned to the workload. This ID is unique within an Amazon Web Services Region.</p>
    pub fn get_workload_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.workload_id
    }
    /// <p>The token to use to retrieve the next set of results.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The token to use to retrieve the next set of results.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>The token to use to retrieve the next set of results.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// <p>The maximum number of results to return for this request.</p>
    pub fn max_results(mut self, input: i32) -> Self {
        self.max_results = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum number of results to return for this request.</p>
    pub fn set_max_results(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_results = input;
        self
    }
    /// <p>The maximum number of results to return for this request.</p>
    pub fn get_max_results(&self) -> &::std::option::Option<i32> {
        &self.max_results
    }
    /// Consumes the builder and constructs a [`ListProfileNotificationsInput`](crate::operation::list_profile_notifications::ListProfileNotificationsInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::list_profile_notifications::ListProfileNotificationsInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::list_profile_notifications::ListProfileNotificationsInput {
            workload_id: self.workload_id,
            next_token: self.next_token,
            max_results: self.max_results,
        })
    }
}
