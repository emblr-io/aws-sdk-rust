// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CountPendingDecisionTasksInput {
    /// <p>The name of the domain that contains the task list.</p>
    pub domain: ::std::option::Option<::std::string::String>,
    /// <p>The name of the task list.</p>
    pub task_list: ::std::option::Option<crate::types::TaskList>,
}
impl CountPendingDecisionTasksInput {
    /// <p>The name of the domain that contains the task list.</p>
    pub fn domain(&self) -> ::std::option::Option<&str> {
        self.domain.as_deref()
    }
    /// <p>The name of the task list.</p>
    pub fn task_list(&self) -> ::std::option::Option<&crate::types::TaskList> {
        self.task_list.as_ref()
    }
}
impl CountPendingDecisionTasksInput {
    /// Creates a new builder-style object to manufacture [`CountPendingDecisionTasksInput`](crate::operation::count_pending_decision_tasks::CountPendingDecisionTasksInput).
    pub fn builder() -> crate::operation::count_pending_decision_tasks::builders::CountPendingDecisionTasksInputBuilder {
        crate::operation::count_pending_decision_tasks::builders::CountPendingDecisionTasksInputBuilder::default()
    }
}

/// A builder for [`CountPendingDecisionTasksInput`](crate::operation::count_pending_decision_tasks::CountPendingDecisionTasksInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CountPendingDecisionTasksInputBuilder {
    pub(crate) domain: ::std::option::Option<::std::string::String>,
    pub(crate) task_list: ::std::option::Option<crate::types::TaskList>,
}
impl CountPendingDecisionTasksInputBuilder {
    /// <p>The name of the domain that contains the task list.</p>
    /// This field is required.
    pub fn domain(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.domain = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the domain that contains the task list.</p>
    pub fn set_domain(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.domain = input;
        self
    }
    /// <p>The name of the domain that contains the task list.</p>
    pub fn get_domain(&self) -> &::std::option::Option<::std::string::String> {
        &self.domain
    }
    /// <p>The name of the task list.</p>
    /// This field is required.
    pub fn task_list(mut self, input: crate::types::TaskList) -> Self {
        self.task_list = ::std::option::Option::Some(input);
        self
    }
    /// <p>The name of the task list.</p>
    pub fn set_task_list(mut self, input: ::std::option::Option<crate::types::TaskList>) -> Self {
        self.task_list = input;
        self
    }
    /// <p>The name of the task list.</p>
    pub fn get_task_list(&self) -> &::std::option::Option<crate::types::TaskList> {
        &self.task_list
    }
    /// Consumes the builder and constructs a [`CountPendingDecisionTasksInput`](crate::operation::count_pending_decision_tasks::CountPendingDecisionTasksInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::count_pending_decision_tasks::CountPendingDecisionTasksInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::count_pending_decision_tasks::CountPendingDecisionTasksInput {
            domain: self.domain,
            task_list: self.task_list,
        })
    }
}
