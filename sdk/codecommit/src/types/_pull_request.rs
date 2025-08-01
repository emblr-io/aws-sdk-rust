// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Returns information about a pull request.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct PullRequest {
    /// <p>The system-generated ID of the pull request.</p>
    pub pull_request_id: ::std::option::Option<::std::string::String>,
    /// <p>The user-defined title of the pull request. This title is displayed in the list of pull requests to other repository users.</p>
    pub title: ::std::option::Option<::std::string::String>,
    /// <p>The user-defined description of the pull request. This description can be used to clarify what should be reviewed and other details of the request.</p>
    pub description: ::std::option::Option<::std::string::String>,
    /// <p>The day and time of the last user or system activity on the pull request, in timestamp format.</p>
    pub last_activity_date: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The date and time the pull request was originally created, in timestamp format.</p>
    pub creation_date: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The status of the pull request. Pull request status can only change from <code>OPEN</code> to <code>CLOSED</code>.</p>
    pub pull_request_status: ::std::option::Option<crate::types::PullRequestStatusEnum>,
    /// <p>The Amazon Resource Name (ARN) of the user who created the pull request.</p>
    pub author_arn: ::std::option::Option<::std::string::String>,
    /// <p>The targets of the pull request, including the source branch and destination branch for the pull request.</p>
    pub pull_request_targets: ::std::option::Option<::std::vec::Vec<crate::types::PullRequestTarget>>,
    /// <p>A unique, client-generated idempotency token that, when provided in a request, ensures the request cannot be repeated with a changed parameter. If a request is received with the same parameters and a token is included, the request returns information about the initial request that used that token.</p>
    pub client_request_token: ::std::option::Option<::std::string::String>,
    /// <p>The system-generated revision ID for the pull request.</p>
    pub revision_id: ::std::option::Option<::std::string::String>,
    /// <p>The approval rules applied to the pull request.</p>
    pub approval_rules: ::std::option::Option<::std::vec::Vec<crate::types::ApprovalRule>>,
}
impl PullRequest {
    /// <p>The system-generated ID of the pull request.</p>
    pub fn pull_request_id(&self) -> ::std::option::Option<&str> {
        self.pull_request_id.as_deref()
    }
    /// <p>The user-defined title of the pull request. This title is displayed in the list of pull requests to other repository users.</p>
    pub fn title(&self) -> ::std::option::Option<&str> {
        self.title.as_deref()
    }
    /// <p>The user-defined description of the pull request. This description can be used to clarify what should be reviewed and other details of the request.</p>
    pub fn description(&self) -> ::std::option::Option<&str> {
        self.description.as_deref()
    }
    /// <p>The day and time of the last user or system activity on the pull request, in timestamp format.</p>
    pub fn last_activity_date(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.last_activity_date.as_ref()
    }
    /// <p>The date and time the pull request was originally created, in timestamp format.</p>
    pub fn creation_date(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.creation_date.as_ref()
    }
    /// <p>The status of the pull request. Pull request status can only change from <code>OPEN</code> to <code>CLOSED</code>.</p>
    pub fn pull_request_status(&self) -> ::std::option::Option<&crate::types::PullRequestStatusEnum> {
        self.pull_request_status.as_ref()
    }
    /// <p>The Amazon Resource Name (ARN) of the user who created the pull request.</p>
    pub fn author_arn(&self) -> ::std::option::Option<&str> {
        self.author_arn.as_deref()
    }
    /// <p>The targets of the pull request, including the source branch and destination branch for the pull request.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.pull_request_targets.is_none()`.
    pub fn pull_request_targets(&self) -> &[crate::types::PullRequestTarget] {
        self.pull_request_targets.as_deref().unwrap_or_default()
    }
    /// <p>A unique, client-generated idempotency token that, when provided in a request, ensures the request cannot be repeated with a changed parameter. If a request is received with the same parameters and a token is included, the request returns information about the initial request that used that token.</p>
    pub fn client_request_token(&self) -> ::std::option::Option<&str> {
        self.client_request_token.as_deref()
    }
    /// <p>The system-generated revision ID for the pull request.</p>
    pub fn revision_id(&self) -> ::std::option::Option<&str> {
        self.revision_id.as_deref()
    }
    /// <p>The approval rules applied to the pull request.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.approval_rules.is_none()`.
    pub fn approval_rules(&self) -> &[crate::types::ApprovalRule] {
        self.approval_rules.as_deref().unwrap_or_default()
    }
}
impl PullRequest {
    /// Creates a new builder-style object to manufacture [`PullRequest`](crate::types::PullRequest).
    pub fn builder() -> crate::types::builders::PullRequestBuilder {
        crate::types::builders::PullRequestBuilder::default()
    }
}

/// A builder for [`PullRequest`](crate::types::PullRequest).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct PullRequestBuilder {
    pub(crate) pull_request_id: ::std::option::Option<::std::string::String>,
    pub(crate) title: ::std::option::Option<::std::string::String>,
    pub(crate) description: ::std::option::Option<::std::string::String>,
    pub(crate) last_activity_date: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) creation_date: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) pull_request_status: ::std::option::Option<crate::types::PullRequestStatusEnum>,
    pub(crate) author_arn: ::std::option::Option<::std::string::String>,
    pub(crate) pull_request_targets: ::std::option::Option<::std::vec::Vec<crate::types::PullRequestTarget>>,
    pub(crate) client_request_token: ::std::option::Option<::std::string::String>,
    pub(crate) revision_id: ::std::option::Option<::std::string::String>,
    pub(crate) approval_rules: ::std::option::Option<::std::vec::Vec<crate::types::ApprovalRule>>,
}
impl PullRequestBuilder {
    /// <p>The system-generated ID of the pull request.</p>
    pub fn pull_request_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.pull_request_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The system-generated ID of the pull request.</p>
    pub fn set_pull_request_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.pull_request_id = input;
        self
    }
    /// <p>The system-generated ID of the pull request.</p>
    pub fn get_pull_request_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.pull_request_id
    }
    /// <p>The user-defined title of the pull request. This title is displayed in the list of pull requests to other repository users.</p>
    pub fn title(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.title = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The user-defined title of the pull request. This title is displayed in the list of pull requests to other repository users.</p>
    pub fn set_title(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.title = input;
        self
    }
    /// <p>The user-defined title of the pull request. This title is displayed in the list of pull requests to other repository users.</p>
    pub fn get_title(&self) -> &::std::option::Option<::std::string::String> {
        &self.title
    }
    /// <p>The user-defined description of the pull request. This description can be used to clarify what should be reviewed and other details of the request.</p>
    pub fn description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The user-defined description of the pull request. This description can be used to clarify what should be reviewed and other details of the request.</p>
    pub fn set_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.description = input;
        self
    }
    /// <p>The user-defined description of the pull request. This description can be used to clarify what should be reviewed and other details of the request.</p>
    pub fn get_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.description
    }
    /// <p>The day and time of the last user or system activity on the pull request, in timestamp format.</p>
    pub fn last_activity_date(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.last_activity_date = ::std::option::Option::Some(input);
        self
    }
    /// <p>The day and time of the last user or system activity on the pull request, in timestamp format.</p>
    pub fn set_last_activity_date(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.last_activity_date = input;
        self
    }
    /// <p>The day and time of the last user or system activity on the pull request, in timestamp format.</p>
    pub fn get_last_activity_date(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.last_activity_date
    }
    /// <p>The date and time the pull request was originally created, in timestamp format.</p>
    pub fn creation_date(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.creation_date = ::std::option::Option::Some(input);
        self
    }
    /// <p>The date and time the pull request was originally created, in timestamp format.</p>
    pub fn set_creation_date(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.creation_date = input;
        self
    }
    /// <p>The date and time the pull request was originally created, in timestamp format.</p>
    pub fn get_creation_date(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.creation_date
    }
    /// <p>The status of the pull request. Pull request status can only change from <code>OPEN</code> to <code>CLOSED</code>.</p>
    pub fn pull_request_status(mut self, input: crate::types::PullRequestStatusEnum) -> Self {
        self.pull_request_status = ::std::option::Option::Some(input);
        self
    }
    /// <p>The status of the pull request. Pull request status can only change from <code>OPEN</code> to <code>CLOSED</code>.</p>
    pub fn set_pull_request_status(mut self, input: ::std::option::Option<crate::types::PullRequestStatusEnum>) -> Self {
        self.pull_request_status = input;
        self
    }
    /// <p>The status of the pull request. Pull request status can only change from <code>OPEN</code> to <code>CLOSED</code>.</p>
    pub fn get_pull_request_status(&self) -> &::std::option::Option<crate::types::PullRequestStatusEnum> {
        &self.pull_request_status
    }
    /// <p>The Amazon Resource Name (ARN) of the user who created the pull request.</p>
    pub fn author_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.author_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the user who created the pull request.</p>
    pub fn set_author_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.author_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the user who created the pull request.</p>
    pub fn get_author_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.author_arn
    }
    /// Appends an item to `pull_request_targets`.
    ///
    /// To override the contents of this collection use [`set_pull_request_targets`](Self::set_pull_request_targets).
    ///
    /// <p>The targets of the pull request, including the source branch and destination branch for the pull request.</p>
    pub fn pull_request_targets(mut self, input: crate::types::PullRequestTarget) -> Self {
        let mut v = self.pull_request_targets.unwrap_or_default();
        v.push(input);
        self.pull_request_targets = ::std::option::Option::Some(v);
        self
    }
    /// <p>The targets of the pull request, including the source branch and destination branch for the pull request.</p>
    pub fn set_pull_request_targets(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::PullRequestTarget>>) -> Self {
        self.pull_request_targets = input;
        self
    }
    /// <p>The targets of the pull request, including the source branch and destination branch for the pull request.</p>
    pub fn get_pull_request_targets(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::PullRequestTarget>> {
        &self.pull_request_targets
    }
    /// <p>A unique, client-generated idempotency token that, when provided in a request, ensures the request cannot be repeated with a changed parameter. If a request is received with the same parameters and a token is included, the request returns information about the initial request that used that token.</p>
    pub fn client_request_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.client_request_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A unique, client-generated idempotency token that, when provided in a request, ensures the request cannot be repeated with a changed parameter. If a request is received with the same parameters and a token is included, the request returns information about the initial request that used that token.</p>
    pub fn set_client_request_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.client_request_token = input;
        self
    }
    /// <p>A unique, client-generated idempotency token that, when provided in a request, ensures the request cannot be repeated with a changed parameter. If a request is received with the same parameters and a token is included, the request returns information about the initial request that used that token.</p>
    pub fn get_client_request_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.client_request_token
    }
    /// <p>The system-generated revision ID for the pull request.</p>
    pub fn revision_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.revision_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The system-generated revision ID for the pull request.</p>
    pub fn set_revision_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.revision_id = input;
        self
    }
    /// <p>The system-generated revision ID for the pull request.</p>
    pub fn get_revision_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.revision_id
    }
    /// Appends an item to `approval_rules`.
    ///
    /// To override the contents of this collection use [`set_approval_rules`](Self::set_approval_rules).
    ///
    /// <p>The approval rules applied to the pull request.</p>
    pub fn approval_rules(mut self, input: crate::types::ApprovalRule) -> Self {
        let mut v = self.approval_rules.unwrap_or_default();
        v.push(input);
        self.approval_rules = ::std::option::Option::Some(v);
        self
    }
    /// <p>The approval rules applied to the pull request.</p>
    pub fn set_approval_rules(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::ApprovalRule>>) -> Self {
        self.approval_rules = input;
        self
    }
    /// <p>The approval rules applied to the pull request.</p>
    pub fn get_approval_rules(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::ApprovalRule>> {
        &self.approval_rules
    }
    /// Consumes the builder and constructs a [`PullRequest`](crate::types::PullRequest).
    pub fn build(self) -> crate::types::PullRequest {
        crate::types::PullRequest {
            pull_request_id: self.pull_request_id,
            title: self.title,
            description: self.description,
            last_activity_date: self.last_activity_date,
            creation_date: self.creation_date,
            pull_request_status: self.pull_request_status,
            author_arn: self.author_arn,
            pull_request_targets: self.pull_request_targets,
            client_request_token: self.client_request_token,
            revision_id: self.revision_id,
            approval_rules: self.approval_rules,
        }
    }
}
