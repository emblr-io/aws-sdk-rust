// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListRecoveryPointsByResourceInput {
    /// <p>An ARN that uniquely identifies a resource. The format of the ARN depends on the resource type.</p>
    pub resource_arn: ::std::option::Option<::std::string::String>,
    /// <p>The next item following a partial list of returned items. For example, if a request is made to return <code>MaxResults</code> number of items, <code>NextToken</code> allows you to return more items in your list starting at the location pointed to by the next token.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    /// <p>The maximum number of items to be returned.</p><note>
    /// <p>Amazon RDS requires a value of at least 20.</p>
    /// </note>
    pub max_results: ::std::option::Option<i32>,
    /// <p>This attribute filters recovery points based on ownership.</p>
    /// <p>If this is set to <code>TRUE</code>, the response will contain recovery points associated with the selected resources that are managed by Backup.</p>
    /// <p>If this is set to <code>FALSE</code>, the response will contain all recovery points associated with the selected resource.</p>
    /// <p>Type: Boolean</p>
    pub managed_by_aws_backup_only: ::std::option::Option<bool>,
}
impl ListRecoveryPointsByResourceInput {
    /// <p>An ARN that uniquely identifies a resource. The format of the ARN depends on the resource type.</p>
    pub fn resource_arn(&self) -> ::std::option::Option<&str> {
        self.resource_arn.as_deref()
    }
    /// <p>The next item following a partial list of returned items. For example, if a request is made to return <code>MaxResults</code> number of items, <code>NextToken</code> allows you to return more items in your list starting at the location pointed to by the next token.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
    /// <p>The maximum number of items to be returned.</p><note>
    /// <p>Amazon RDS requires a value of at least 20.</p>
    /// </note>
    pub fn max_results(&self) -> ::std::option::Option<i32> {
        self.max_results
    }
    /// <p>This attribute filters recovery points based on ownership.</p>
    /// <p>If this is set to <code>TRUE</code>, the response will contain recovery points associated with the selected resources that are managed by Backup.</p>
    /// <p>If this is set to <code>FALSE</code>, the response will contain all recovery points associated with the selected resource.</p>
    /// <p>Type: Boolean</p>
    pub fn managed_by_aws_backup_only(&self) -> ::std::option::Option<bool> {
        self.managed_by_aws_backup_only
    }
}
impl ListRecoveryPointsByResourceInput {
    /// Creates a new builder-style object to manufacture [`ListRecoveryPointsByResourceInput`](crate::operation::list_recovery_points_by_resource::ListRecoveryPointsByResourceInput).
    pub fn builder() -> crate::operation::list_recovery_points_by_resource::builders::ListRecoveryPointsByResourceInputBuilder {
        crate::operation::list_recovery_points_by_resource::builders::ListRecoveryPointsByResourceInputBuilder::default()
    }
}

/// A builder for [`ListRecoveryPointsByResourceInput`](crate::operation::list_recovery_points_by_resource::ListRecoveryPointsByResourceInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListRecoveryPointsByResourceInputBuilder {
    pub(crate) resource_arn: ::std::option::Option<::std::string::String>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    pub(crate) max_results: ::std::option::Option<i32>,
    pub(crate) managed_by_aws_backup_only: ::std::option::Option<bool>,
}
impl ListRecoveryPointsByResourceInputBuilder {
    /// <p>An ARN that uniquely identifies a resource. The format of the ARN depends on the resource type.</p>
    /// This field is required.
    pub fn resource_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.resource_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>An ARN that uniquely identifies a resource. The format of the ARN depends on the resource type.</p>
    pub fn set_resource_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.resource_arn = input;
        self
    }
    /// <p>An ARN that uniquely identifies a resource. The format of the ARN depends on the resource type.</p>
    pub fn get_resource_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.resource_arn
    }
    /// <p>The next item following a partial list of returned items. For example, if a request is made to return <code>MaxResults</code> number of items, <code>NextToken</code> allows you to return more items in your list starting at the location pointed to by the next token.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The next item following a partial list of returned items. For example, if a request is made to return <code>MaxResults</code> number of items, <code>NextToken</code> allows you to return more items in your list starting at the location pointed to by the next token.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>The next item following a partial list of returned items. For example, if a request is made to return <code>MaxResults</code> number of items, <code>NextToken</code> allows you to return more items in your list starting at the location pointed to by the next token.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// <p>The maximum number of items to be returned.</p><note>
    /// <p>Amazon RDS requires a value of at least 20.</p>
    /// </note>
    pub fn max_results(mut self, input: i32) -> Self {
        self.max_results = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum number of items to be returned.</p><note>
    /// <p>Amazon RDS requires a value of at least 20.</p>
    /// </note>
    pub fn set_max_results(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_results = input;
        self
    }
    /// <p>The maximum number of items to be returned.</p><note>
    /// <p>Amazon RDS requires a value of at least 20.</p>
    /// </note>
    pub fn get_max_results(&self) -> &::std::option::Option<i32> {
        &self.max_results
    }
    /// <p>This attribute filters recovery points based on ownership.</p>
    /// <p>If this is set to <code>TRUE</code>, the response will contain recovery points associated with the selected resources that are managed by Backup.</p>
    /// <p>If this is set to <code>FALSE</code>, the response will contain all recovery points associated with the selected resource.</p>
    /// <p>Type: Boolean</p>
    pub fn managed_by_aws_backup_only(mut self, input: bool) -> Self {
        self.managed_by_aws_backup_only = ::std::option::Option::Some(input);
        self
    }
    /// <p>This attribute filters recovery points based on ownership.</p>
    /// <p>If this is set to <code>TRUE</code>, the response will contain recovery points associated with the selected resources that are managed by Backup.</p>
    /// <p>If this is set to <code>FALSE</code>, the response will contain all recovery points associated with the selected resource.</p>
    /// <p>Type: Boolean</p>
    pub fn set_managed_by_aws_backup_only(mut self, input: ::std::option::Option<bool>) -> Self {
        self.managed_by_aws_backup_only = input;
        self
    }
    /// <p>This attribute filters recovery points based on ownership.</p>
    /// <p>If this is set to <code>TRUE</code>, the response will contain recovery points associated with the selected resources that are managed by Backup.</p>
    /// <p>If this is set to <code>FALSE</code>, the response will contain all recovery points associated with the selected resource.</p>
    /// <p>Type: Boolean</p>
    pub fn get_managed_by_aws_backup_only(&self) -> &::std::option::Option<bool> {
        &self.managed_by_aws_backup_only
    }
    /// Consumes the builder and constructs a [`ListRecoveryPointsByResourceInput`](crate::operation::list_recovery_points_by_resource::ListRecoveryPointsByResourceInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::list_recovery_points_by_resource::ListRecoveryPointsByResourceInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::list_recovery_points_by_resource::ListRecoveryPointsByResourceInput {
            resource_arn: self.resource_arn,
            next_token: self.next_token,
            max_results: self.max_results,
            managed_by_aws_backup_only: self.managed_by_aws_backup_only,
        })
    }
}
