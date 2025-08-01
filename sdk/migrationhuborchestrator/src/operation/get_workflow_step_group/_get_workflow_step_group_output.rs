// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetWorkflowStepGroupOutput {
    /// <p>The ID of the step group.</p>
    pub id: ::std::option::Option<::std::string::String>,
    /// <p>The ID of the migration workflow.</p>
    pub workflow_id: ::std::option::Option<::std::string::String>,
    /// <p>The name of the step group.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>The description of the step group.</p>
    pub description: ::std::option::Option<::std::string::String>,
    /// <p>The status of the step group.</p>
    pub status: ::std::option::Option<crate::types::StepGroupStatus>,
    /// <p>The owner of the step group.</p>
    pub owner: ::std::option::Option<crate::types::Owner>,
    /// <p>The time at which the step group was created.</p>
    pub creation_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The time at which the step group was last modified.</p>
    pub last_modified_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The time at which the step group ended.</p>
    pub end_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>List of AWS services utilized in a migration workflow.</p>
    pub tools: ::std::option::Option<::std::vec::Vec<crate::types::Tool>>,
    /// <p>The previous step group.</p>
    pub previous: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>The next step group.</p>
    pub next: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    _request_id: Option<String>,
}
impl GetWorkflowStepGroupOutput {
    /// <p>The ID of the step group.</p>
    pub fn id(&self) -> ::std::option::Option<&str> {
        self.id.as_deref()
    }
    /// <p>The ID of the migration workflow.</p>
    pub fn workflow_id(&self) -> ::std::option::Option<&str> {
        self.workflow_id.as_deref()
    }
    /// <p>The name of the step group.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>The description of the step group.</p>
    pub fn description(&self) -> ::std::option::Option<&str> {
        self.description.as_deref()
    }
    /// <p>The status of the step group.</p>
    pub fn status(&self) -> ::std::option::Option<&crate::types::StepGroupStatus> {
        self.status.as_ref()
    }
    /// <p>The owner of the step group.</p>
    pub fn owner(&self) -> ::std::option::Option<&crate::types::Owner> {
        self.owner.as_ref()
    }
    /// <p>The time at which the step group was created.</p>
    pub fn creation_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.creation_time.as_ref()
    }
    /// <p>The time at which the step group was last modified.</p>
    pub fn last_modified_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.last_modified_time.as_ref()
    }
    /// <p>The time at which the step group ended.</p>
    pub fn end_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.end_time.as_ref()
    }
    /// <p>List of AWS services utilized in a migration workflow.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.tools.is_none()`.
    pub fn tools(&self) -> &[crate::types::Tool] {
        self.tools.as_deref().unwrap_or_default()
    }
    /// <p>The previous step group.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.previous.is_none()`.
    pub fn previous(&self) -> &[::std::string::String] {
        self.previous.as_deref().unwrap_or_default()
    }
    /// <p>The next step group.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.next.is_none()`.
    pub fn next(&self) -> &[::std::string::String] {
        self.next.as_deref().unwrap_or_default()
    }
}
impl ::aws_types::request_id::RequestId for GetWorkflowStepGroupOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl GetWorkflowStepGroupOutput {
    /// Creates a new builder-style object to manufacture [`GetWorkflowStepGroupOutput`](crate::operation::get_workflow_step_group::GetWorkflowStepGroupOutput).
    pub fn builder() -> crate::operation::get_workflow_step_group::builders::GetWorkflowStepGroupOutputBuilder {
        crate::operation::get_workflow_step_group::builders::GetWorkflowStepGroupOutputBuilder::default()
    }
}

/// A builder for [`GetWorkflowStepGroupOutput`](crate::operation::get_workflow_step_group::GetWorkflowStepGroupOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetWorkflowStepGroupOutputBuilder {
    pub(crate) id: ::std::option::Option<::std::string::String>,
    pub(crate) workflow_id: ::std::option::Option<::std::string::String>,
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) description: ::std::option::Option<::std::string::String>,
    pub(crate) status: ::std::option::Option<crate::types::StepGroupStatus>,
    pub(crate) owner: ::std::option::Option<crate::types::Owner>,
    pub(crate) creation_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) last_modified_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) end_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) tools: ::std::option::Option<::std::vec::Vec<crate::types::Tool>>,
    pub(crate) previous: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) next: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    _request_id: Option<String>,
}
impl GetWorkflowStepGroupOutputBuilder {
    /// <p>The ID of the step group.</p>
    pub fn id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the step group.</p>
    pub fn set_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.id = input;
        self
    }
    /// <p>The ID of the step group.</p>
    pub fn get_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.id
    }
    /// <p>The ID of the migration workflow.</p>
    pub fn workflow_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.workflow_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the migration workflow.</p>
    pub fn set_workflow_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.workflow_id = input;
        self
    }
    /// <p>The ID of the migration workflow.</p>
    pub fn get_workflow_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.workflow_id
    }
    /// <p>The name of the step group.</p>
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the step group.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the step group.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>The description of the step group.</p>
    pub fn description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The description of the step group.</p>
    pub fn set_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.description = input;
        self
    }
    /// <p>The description of the step group.</p>
    pub fn get_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.description
    }
    /// <p>The status of the step group.</p>
    pub fn status(mut self, input: crate::types::StepGroupStatus) -> Self {
        self.status = ::std::option::Option::Some(input);
        self
    }
    /// <p>The status of the step group.</p>
    pub fn set_status(mut self, input: ::std::option::Option<crate::types::StepGroupStatus>) -> Self {
        self.status = input;
        self
    }
    /// <p>The status of the step group.</p>
    pub fn get_status(&self) -> &::std::option::Option<crate::types::StepGroupStatus> {
        &self.status
    }
    /// <p>The owner of the step group.</p>
    pub fn owner(mut self, input: crate::types::Owner) -> Self {
        self.owner = ::std::option::Option::Some(input);
        self
    }
    /// <p>The owner of the step group.</p>
    pub fn set_owner(mut self, input: ::std::option::Option<crate::types::Owner>) -> Self {
        self.owner = input;
        self
    }
    /// <p>The owner of the step group.</p>
    pub fn get_owner(&self) -> &::std::option::Option<crate::types::Owner> {
        &self.owner
    }
    /// <p>The time at which the step group was created.</p>
    pub fn creation_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.creation_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The time at which the step group was created.</p>
    pub fn set_creation_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.creation_time = input;
        self
    }
    /// <p>The time at which the step group was created.</p>
    pub fn get_creation_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.creation_time
    }
    /// <p>The time at which the step group was last modified.</p>
    pub fn last_modified_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.last_modified_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The time at which the step group was last modified.</p>
    pub fn set_last_modified_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.last_modified_time = input;
        self
    }
    /// <p>The time at which the step group was last modified.</p>
    pub fn get_last_modified_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.last_modified_time
    }
    /// <p>The time at which the step group ended.</p>
    pub fn end_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.end_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The time at which the step group ended.</p>
    pub fn set_end_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.end_time = input;
        self
    }
    /// <p>The time at which the step group ended.</p>
    pub fn get_end_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.end_time
    }
    /// Appends an item to `tools`.
    ///
    /// To override the contents of this collection use [`set_tools`](Self::set_tools).
    ///
    /// <p>List of AWS services utilized in a migration workflow.</p>
    pub fn tools(mut self, input: crate::types::Tool) -> Self {
        let mut v = self.tools.unwrap_or_default();
        v.push(input);
        self.tools = ::std::option::Option::Some(v);
        self
    }
    /// <p>List of AWS services utilized in a migration workflow.</p>
    pub fn set_tools(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Tool>>) -> Self {
        self.tools = input;
        self
    }
    /// <p>List of AWS services utilized in a migration workflow.</p>
    pub fn get_tools(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Tool>> {
        &self.tools
    }
    /// Appends an item to `previous`.
    ///
    /// To override the contents of this collection use [`set_previous`](Self::set_previous).
    ///
    /// <p>The previous step group.</p>
    pub fn previous(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.previous.unwrap_or_default();
        v.push(input.into());
        self.previous = ::std::option::Option::Some(v);
        self
    }
    /// <p>The previous step group.</p>
    pub fn set_previous(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.previous = input;
        self
    }
    /// <p>The previous step group.</p>
    pub fn get_previous(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.previous
    }
    /// Appends an item to `next`.
    ///
    /// To override the contents of this collection use [`set_next`](Self::set_next).
    ///
    /// <p>The next step group.</p>
    pub fn next(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.next.unwrap_or_default();
        v.push(input.into());
        self.next = ::std::option::Option::Some(v);
        self
    }
    /// <p>The next step group.</p>
    pub fn set_next(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.next = input;
        self
    }
    /// <p>The next step group.</p>
    pub fn get_next(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.next
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`GetWorkflowStepGroupOutput`](crate::operation::get_workflow_step_group::GetWorkflowStepGroupOutput).
    pub fn build(self) -> crate::operation::get_workflow_step_group::GetWorkflowStepGroupOutput {
        crate::operation::get_workflow_step_group::GetWorkflowStepGroupOutput {
            id: self.id,
            workflow_id: self.workflow_id,
            name: self.name,
            description: self.description,
            status: self.status,
            owner: self.owner,
            creation_time: self.creation_time,
            last_modified_time: self.last_modified_time,
            end_time: self.end_time,
            tools: self.tools,
            previous: self.previous,
            next: self.next,
            _request_id: self._request_id,
        }
    }
}
