// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListNotificationsInput {
    /// <p>The ID assigned to the workload. This ID is unique within an Amazon Web Services Region.</p>
    pub workload_id: ::std::option::Option<::std::string::String>,
    /// <p>The token to use to retrieve the next set of results.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    /// <p>The maximum number of results to return for this request.</p>
    pub max_results: ::std::option::Option<i32>,
    /// <p>The ARN for the related resource for the notification.</p><note>
    /// <p>Only one of <code>WorkloadID</code> or <code>ResourceARN</code> should be specified.</p>
    /// </note>
    pub resource_arn: ::std::option::Option<::std::string::String>,
}
impl ListNotificationsInput {
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
    /// <p>The ARN for the related resource for the notification.</p><note>
    /// <p>Only one of <code>WorkloadID</code> or <code>ResourceARN</code> should be specified.</p>
    /// </note>
    pub fn resource_arn(&self) -> ::std::option::Option<&str> {
        self.resource_arn.as_deref()
    }
}
impl ListNotificationsInput {
    /// Creates a new builder-style object to manufacture [`ListNotificationsInput`](crate::operation::list_notifications::ListNotificationsInput).
    pub fn builder() -> crate::operation::list_notifications::builders::ListNotificationsInputBuilder {
        crate::operation::list_notifications::builders::ListNotificationsInputBuilder::default()
    }
}

/// A builder for [`ListNotificationsInput`](crate::operation::list_notifications::ListNotificationsInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListNotificationsInputBuilder {
    pub(crate) workload_id: ::std::option::Option<::std::string::String>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    pub(crate) max_results: ::std::option::Option<i32>,
    pub(crate) resource_arn: ::std::option::Option<::std::string::String>,
}
impl ListNotificationsInputBuilder {
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
    /// <p>The ARN for the related resource for the notification.</p><note>
    /// <p>Only one of <code>WorkloadID</code> or <code>ResourceARN</code> should be specified.</p>
    /// </note>
    pub fn resource_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.resource_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ARN for the related resource for the notification.</p><note>
    /// <p>Only one of <code>WorkloadID</code> or <code>ResourceARN</code> should be specified.</p>
    /// </note>
    pub fn set_resource_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.resource_arn = input;
        self
    }
    /// <p>The ARN for the related resource for the notification.</p><note>
    /// <p>Only one of <code>WorkloadID</code> or <code>ResourceARN</code> should be specified.</p>
    /// </note>
    pub fn get_resource_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.resource_arn
    }
    /// Consumes the builder and constructs a [`ListNotificationsInput`](crate::operation::list_notifications::ListNotificationsInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::list_notifications::ListNotificationsInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::list_notifications::ListNotificationsInput {
            workload_id: self.workload_id,
            next_token: self.next_token,
            max_results: self.max_results,
            resource_arn: self.resource_arn,
        })
    }
}
