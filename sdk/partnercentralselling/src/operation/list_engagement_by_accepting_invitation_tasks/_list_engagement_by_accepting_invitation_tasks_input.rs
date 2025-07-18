// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListEngagementByAcceptingInvitationTasksInput {
    /// <p>Use this parameter to control the number of items returned in each request, which can be useful for performance tuning and managing large result sets.</p>
    pub max_results: ::std::option::Option<i32>,
    /// <p>Use this parameter for pagination when the result set spans multiple pages. This value is obtained from the NextToken field in the response of a previous call to this API.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    /// <p>Specifies the sorting criteria for the returned results. This allows you to order the tasks based on specific attributes.</p>
    pub sort: ::std::option::Option<crate::types::ListTasksSortBase>,
    /// <p>Specifies the catalog related to the request. Valid values are:</p>
    /// <ul>
    /// <li>
    /// <p>AWS: Retrieves the request from the production AWS environment.</p></li>
    /// <li>
    /// <p>Sandbox: Retrieves the request from a sandbox environment used for testing or development purposes.</p></li>
    /// </ul>
    pub catalog: ::std::option::Option<::std::string::String>,
    /// <p>Filters the tasks based on their current status. This allows you to focus on tasks in specific states.</p>
    pub task_status: ::std::option::Option<::std::vec::Vec<crate::types::TaskStatus>>,
    /// <p>Filters tasks by the identifiers of the opportunities they created or are associated with.</p>
    pub opportunity_identifier: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>Filters tasks by the identifiers of the engagement invitations they are processing.</p>
    pub engagement_invitation_identifier: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>Filters tasks by their unique identifiers. Use this when you want to retrieve information about specific tasks.</p>
    pub task_identifier: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl ListEngagementByAcceptingInvitationTasksInput {
    /// <p>Use this parameter to control the number of items returned in each request, which can be useful for performance tuning and managing large result sets.</p>
    pub fn max_results(&self) -> ::std::option::Option<i32> {
        self.max_results
    }
    /// <p>Use this parameter for pagination when the result set spans multiple pages. This value is obtained from the NextToken field in the response of a previous call to this API.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
    /// <p>Specifies the sorting criteria for the returned results. This allows you to order the tasks based on specific attributes.</p>
    pub fn sort(&self) -> ::std::option::Option<&crate::types::ListTasksSortBase> {
        self.sort.as_ref()
    }
    /// <p>Specifies the catalog related to the request. Valid values are:</p>
    /// <ul>
    /// <li>
    /// <p>AWS: Retrieves the request from the production AWS environment.</p></li>
    /// <li>
    /// <p>Sandbox: Retrieves the request from a sandbox environment used for testing or development purposes.</p></li>
    /// </ul>
    pub fn catalog(&self) -> ::std::option::Option<&str> {
        self.catalog.as_deref()
    }
    /// <p>Filters the tasks based on their current status. This allows you to focus on tasks in specific states.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.task_status.is_none()`.
    pub fn task_status(&self) -> &[crate::types::TaskStatus] {
        self.task_status.as_deref().unwrap_or_default()
    }
    /// <p>Filters tasks by the identifiers of the opportunities they created or are associated with.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.opportunity_identifier.is_none()`.
    pub fn opportunity_identifier(&self) -> &[::std::string::String] {
        self.opportunity_identifier.as_deref().unwrap_or_default()
    }
    /// <p>Filters tasks by the identifiers of the engagement invitations they are processing.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.engagement_invitation_identifier.is_none()`.
    pub fn engagement_invitation_identifier(&self) -> &[::std::string::String] {
        self.engagement_invitation_identifier.as_deref().unwrap_or_default()
    }
    /// <p>Filters tasks by their unique identifiers. Use this when you want to retrieve information about specific tasks.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.task_identifier.is_none()`.
    pub fn task_identifier(&self) -> &[::std::string::String] {
        self.task_identifier.as_deref().unwrap_or_default()
    }
}
impl ListEngagementByAcceptingInvitationTasksInput {
    /// Creates a new builder-style object to manufacture [`ListEngagementByAcceptingInvitationTasksInput`](crate::operation::list_engagement_by_accepting_invitation_tasks::ListEngagementByAcceptingInvitationTasksInput).
    pub fn builder() -> crate::operation::list_engagement_by_accepting_invitation_tasks::builders::ListEngagementByAcceptingInvitationTasksInputBuilder
    {
        crate::operation::list_engagement_by_accepting_invitation_tasks::builders::ListEngagementByAcceptingInvitationTasksInputBuilder::default()
    }
}

/// A builder for [`ListEngagementByAcceptingInvitationTasksInput`](crate::operation::list_engagement_by_accepting_invitation_tasks::ListEngagementByAcceptingInvitationTasksInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListEngagementByAcceptingInvitationTasksInputBuilder {
    pub(crate) max_results: ::std::option::Option<i32>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    pub(crate) sort: ::std::option::Option<crate::types::ListTasksSortBase>,
    pub(crate) catalog: ::std::option::Option<::std::string::String>,
    pub(crate) task_status: ::std::option::Option<::std::vec::Vec<crate::types::TaskStatus>>,
    pub(crate) opportunity_identifier: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) engagement_invitation_identifier: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) task_identifier: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl ListEngagementByAcceptingInvitationTasksInputBuilder {
    /// <p>Use this parameter to control the number of items returned in each request, which can be useful for performance tuning and managing large result sets.</p>
    pub fn max_results(mut self, input: i32) -> Self {
        self.max_results = ::std::option::Option::Some(input);
        self
    }
    /// <p>Use this parameter to control the number of items returned in each request, which can be useful for performance tuning and managing large result sets.</p>
    pub fn set_max_results(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_results = input;
        self
    }
    /// <p>Use this parameter to control the number of items returned in each request, which can be useful for performance tuning and managing large result sets.</p>
    pub fn get_max_results(&self) -> &::std::option::Option<i32> {
        &self.max_results
    }
    /// <p>Use this parameter for pagination when the result set spans multiple pages. This value is obtained from the NextToken field in the response of a previous call to this API.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Use this parameter for pagination when the result set spans multiple pages. This value is obtained from the NextToken field in the response of a previous call to this API.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>Use this parameter for pagination when the result set spans multiple pages. This value is obtained from the NextToken field in the response of a previous call to this API.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// <p>Specifies the sorting criteria for the returned results. This allows you to order the tasks based on specific attributes.</p>
    pub fn sort(mut self, input: crate::types::ListTasksSortBase) -> Self {
        self.sort = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies the sorting criteria for the returned results. This allows you to order the tasks based on specific attributes.</p>
    pub fn set_sort(mut self, input: ::std::option::Option<crate::types::ListTasksSortBase>) -> Self {
        self.sort = input;
        self
    }
    /// <p>Specifies the sorting criteria for the returned results. This allows you to order the tasks based on specific attributes.</p>
    pub fn get_sort(&self) -> &::std::option::Option<crate::types::ListTasksSortBase> {
        &self.sort
    }
    /// <p>Specifies the catalog related to the request. Valid values are:</p>
    /// <ul>
    /// <li>
    /// <p>AWS: Retrieves the request from the production AWS environment.</p></li>
    /// <li>
    /// <p>Sandbox: Retrieves the request from a sandbox environment used for testing or development purposes.</p></li>
    /// </ul>
    /// This field is required.
    pub fn catalog(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.catalog = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Specifies the catalog related to the request. Valid values are:</p>
    /// <ul>
    /// <li>
    /// <p>AWS: Retrieves the request from the production AWS environment.</p></li>
    /// <li>
    /// <p>Sandbox: Retrieves the request from a sandbox environment used for testing or development purposes.</p></li>
    /// </ul>
    pub fn set_catalog(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.catalog = input;
        self
    }
    /// <p>Specifies the catalog related to the request. Valid values are:</p>
    /// <ul>
    /// <li>
    /// <p>AWS: Retrieves the request from the production AWS environment.</p></li>
    /// <li>
    /// <p>Sandbox: Retrieves the request from a sandbox environment used for testing or development purposes.</p></li>
    /// </ul>
    pub fn get_catalog(&self) -> &::std::option::Option<::std::string::String> {
        &self.catalog
    }
    /// Appends an item to `task_status`.
    ///
    /// To override the contents of this collection use [`set_task_status`](Self::set_task_status).
    ///
    /// <p>Filters the tasks based on their current status. This allows you to focus on tasks in specific states.</p>
    pub fn task_status(mut self, input: crate::types::TaskStatus) -> Self {
        let mut v = self.task_status.unwrap_or_default();
        v.push(input);
        self.task_status = ::std::option::Option::Some(v);
        self
    }
    /// <p>Filters the tasks based on their current status. This allows you to focus on tasks in specific states.</p>
    pub fn set_task_status(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::TaskStatus>>) -> Self {
        self.task_status = input;
        self
    }
    /// <p>Filters the tasks based on their current status. This allows you to focus on tasks in specific states.</p>
    pub fn get_task_status(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::TaskStatus>> {
        &self.task_status
    }
    /// Appends an item to `opportunity_identifier`.
    ///
    /// To override the contents of this collection use [`set_opportunity_identifier`](Self::set_opportunity_identifier).
    ///
    /// <p>Filters tasks by the identifiers of the opportunities they created or are associated with.</p>
    pub fn opportunity_identifier(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.opportunity_identifier.unwrap_or_default();
        v.push(input.into());
        self.opportunity_identifier = ::std::option::Option::Some(v);
        self
    }
    /// <p>Filters tasks by the identifiers of the opportunities they created or are associated with.</p>
    pub fn set_opportunity_identifier(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.opportunity_identifier = input;
        self
    }
    /// <p>Filters tasks by the identifiers of the opportunities they created or are associated with.</p>
    pub fn get_opportunity_identifier(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.opportunity_identifier
    }
    /// Appends an item to `engagement_invitation_identifier`.
    ///
    /// To override the contents of this collection use [`set_engagement_invitation_identifier`](Self::set_engagement_invitation_identifier).
    ///
    /// <p>Filters tasks by the identifiers of the engagement invitations they are processing.</p>
    pub fn engagement_invitation_identifier(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.engagement_invitation_identifier.unwrap_or_default();
        v.push(input.into());
        self.engagement_invitation_identifier = ::std::option::Option::Some(v);
        self
    }
    /// <p>Filters tasks by the identifiers of the engagement invitations they are processing.</p>
    pub fn set_engagement_invitation_identifier(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.engagement_invitation_identifier = input;
        self
    }
    /// <p>Filters tasks by the identifiers of the engagement invitations they are processing.</p>
    pub fn get_engagement_invitation_identifier(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.engagement_invitation_identifier
    }
    /// Appends an item to `task_identifier`.
    ///
    /// To override the contents of this collection use [`set_task_identifier`](Self::set_task_identifier).
    ///
    /// <p>Filters tasks by their unique identifiers. Use this when you want to retrieve information about specific tasks.</p>
    pub fn task_identifier(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.task_identifier.unwrap_or_default();
        v.push(input.into());
        self.task_identifier = ::std::option::Option::Some(v);
        self
    }
    /// <p>Filters tasks by their unique identifiers. Use this when you want to retrieve information about specific tasks.</p>
    pub fn set_task_identifier(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.task_identifier = input;
        self
    }
    /// <p>Filters tasks by their unique identifiers. Use this when you want to retrieve information about specific tasks.</p>
    pub fn get_task_identifier(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.task_identifier
    }
    /// Consumes the builder and constructs a [`ListEngagementByAcceptingInvitationTasksInput`](crate::operation::list_engagement_by_accepting_invitation_tasks::ListEngagementByAcceptingInvitationTasksInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::list_engagement_by_accepting_invitation_tasks::ListEngagementByAcceptingInvitationTasksInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(
            crate::operation::list_engagement_by_accepting_invitation_tasks::ListEngagementByAcceptingInvitationTasksInput {
                max_results: self.max_results,
                next_token: self.next_token,
                sort: self.sort,
                catalog: self.catalog,
                task_status: self.task_status,
                opportunity_identifier: self.opportunity_identifier,
                engagement_invitation_identifier: self.engagement_invitation_identifier,
                task_identifier: self.task_identifier,
            },
        )
    }
}
