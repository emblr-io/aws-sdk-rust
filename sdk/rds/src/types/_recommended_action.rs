// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The recommended actions to apply to resolve the issues associated with your DB instances, DB clusters, and DB parameter groups.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct RecommendedAction {
    /// <p>The unique identifier of the recommended action.</p>
    pub action_id: ::std::option::Option<::std::string::String>,
    /// <p>A short description to summarize the action. The description might contain markdown.</p>
    pub title: ::std::option::Option<::std::string::String>,
    /// <p>A detailed description of the action. The description might contain markdown.</p>
    pub description: ::std::option::Option<::std::string::String>,
    /// <p>An API operation for the action.</p>
    pub operation: ::std::option::Option<::std::string::String>,
    /// <p>The parameters for the API operation.</p>
    pub parameters: ::std::option::Option<::std::vec::Vec<crate::types::RecommendedActionParameter>>,
    /// <p>The methods to apply the recommended action.</p>
    /// <p>Valid values:</p>
    /// <ul>
    /// <li>
    /// <p><code>manual</code> - The action requires you to resolve the recommendation manually.</p></li>
    /// <li>
    /// <p><code>immediately</code> - The action is applied immediately.</p></li>
    /// <li>
    /// <p><code>next-maintainance-window</code> - The action is applied during the next scheduled maintainance.</p></li>
    /// </ul>
    pub apply_modes: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>The status of the action.</p>
    /// <ul>
    /// <li>
    /// <p><code>ready</code></p></li>
    /// <li>
    /// <p><code>applied</code></p></li>
    /// <li>
    /// <p><code>scheduled</code></p></li>
    /// <li>
    /// <p><code>resolved</code></p></li>
    /// </ul>
    pub status: ::std::option::Option<::std::string::String>,
    /// <p>The details of the issue.</p>
    pub issue_details: ::std::option::Option<crate::types::IssueDetails>,
    /// <p>The supporting attributes to explain the recommended action.</p>
    pub context_attributes: ::std::option::Option<::std::vec::Vec<crate::types::ContextAttribute>>,
}
impl RecommendedAction {
    /// <p>The unique identifier of the recommended action.</p>
    pub fn action_id(&self) -> ::std::option::Option<&str> {
        self.action_id.as_deref()
    }
    /// <p>A short description to summarize the action. The description might contain markdown.</p>
    pub fn title(&self) -> ::std::option::Option<&str> {
        self.title.as_deref()
    }
    /// <p>A detailed description of the action. The description might contain markdown.</p>
    pub fn description(&self) -> ::std::option::Option<&str> {
        self.description.as_deref()
    }
    /// <p>An API operation for the action.</p>
    pub fn operation(&self) -> ::std::option::Option<&str> {
        self.operation.as_deref()
    }
    /// <p>The parameters for the API operation.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.parameters.is_none()`.
    pub fn parameters(&self) -> &[crate::types::RecommendedActionParameter] {
        self.parameters.as_deref().unwrap_or_default()
    }
    /// <p>The methods to apply the recommended action.</p>
    /// <p>Valid values:</p>
    /// <ul>
    /// <li>
    /// <p><code>manual</code> - The action requires you to resolve the recommendation manually.</p></li>
    /// <li>
    /// <p><code>immediately</code> - The action is applied immediately.</p></li>
    /// <li>
    /// <p><code>next-maintainance-window</code> - The action is applied during the next scheduled maintainance.</p></li>
    /// </ul>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.apply_modes.is_none()`.
    pub fn apply_modes(&self) -> &[::std::string::String] {
        self.apply_modes.as_deref().unwrap_or_default()
    }
    /// <p>The status of the action.</p>
    /// <ul>
    /// <li>
    /// <p><code>ready</code></p></li>
    /// <li>
    /// <p><code>applied</code></p></li>
    /// <li>
    /// <p><code>scheduled</code></p></li>
    /// <li>
    /// <p><code>resolved</code></p></li>
    /// </ul>
    pub fn status(&self) -> ::std::option::Option<&str> {
        self.status.as_deref()
    }
    /// <p>The details of the issue.</p>
    pub fn issue_details(&self) -> ::std::option::Option<&crate::types::IssueDetails> {
        self.issue_details.as_ref()
    }
    /// <p>The supporting attributes to explain the recommended action.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.context_attributes.is_none()`.
    pub fn context_attributes(&self) -> &[crate::types::ContextAttribute] {
        self.context_attributes.as_deref().unwrap_or_default()
    }
}
impl RecommendedAction {
    /// Creates a new builder-style object to manufacture [`RecommendedAction`](crate::types::RecommendedAction).
    pub fn builder() -> crate::types::builders::RecommendedActionBuilder {
        crate::types::builders::RecommendedActionBuilder::default()
    }
}

/// A builder for [`RecommendedAction`](crate::types::RecommendedAction).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct RecommendedActionBuilder {
    pub(crate) action_id: ::std::option::Option<::std::string::String>,
    pub(crate) title: ::std::option::Option<::std::string::String>,
    pub(crate) description: ::std::option::Option<::std::string::String>,
    pub(crate) operation: ::std::option::Option<::std::string::String>,
    pub(crate) parameters: ::std::option::Option<::std::vec::Vec<crate::types::RecommendedActionParameter>>,
    pub(crate) apply_modes: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) status: ::std::option::Option<::std::string::String>,
    pub(crate) issue_details: ::std::option::Option<crate::types::IssueDetails>,
    pub(crate) context_attributes: ::std::option::Option<::std::vec::Vec<crate::types::ContextAttribute>>,
}
impl RecommendedActionBuilder {
    /// <p>The unique identifier of the recommended action.</p>
    pub fn action_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.action_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique identifier of the recommended action.</p>
    pub fn set_action_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.action_id = input;
        self
    }
    /// <p>The unique identifier of the recommended action.</p>
    pub fn get_action_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.action_id
    }
    /// <p>A short description to summarize the action. The description might contain markdown.</p>
    pub fn title(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.title = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A short description to summarize the action. The description might contain markdown.</p>
    pub fn set_title(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.title = input;
        self
    }
    /// <p>A short description to summarize the action. The description might contain markdown.</p>
    pub fn get_title(&self) -> &::std::option::Option<::std::string::String> {
        &self.title
    }
    /// <p>A detailed description of the action. The description might contain markdown.</p>
    pub fn description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A detailed description of the action. The description might contain markdown.</p>
    pub fn set_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.description = input;
        self
    }
    /// <p>A detailed description of the action. The description might contain markdown.</p>
    pub fn get_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.description
    }
    /// <p>An API operation for the action.</p>
    pub fn operation(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.operation = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>An API operation for the action.</p>
    pub fn set_operation(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.operation = input;
        self
    }
    /// <p>An API operation for the action.</p>
    pub fn get_operation(&self) -> &::std::option::Option<::std::string::String> {
        &self.operation
    }
    /// Appends an item to `parameters`.
    ///
    /// To override the contents of this collection use [`set_parameters`](Self::set_parameters).
    ///
    /// <p>The parameters for the API operation.</p>
    pub fn parameters(mut self, input: crate::types::RecommendedActionParameter) -> Self {
        let mut v = self.parameters.unwrap_or_default();
        v.push(input);
        self.parameters = ::std::option::Option::Some(v);
        self
    }
    /// <p>The parameters for the API operation.</p>
    pub fn set_parameters(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::RecommendedActionParameter>>) -> Self {
        self.parameters = input;
        self
    }
    /// <p>The parameters for the API operation.</p>
    pub fn get_parameters(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::RecommendedActionParameter>> {
        &self.parameters
    }
    /// Appends an item to `apply_modes`.
    ///
    /// To override the contents of this collection use [`set_apply_modes`](Self::set_apply_modes).
    ///
    /// <p>The methods to apply the recommended action.</p>
    /// <p>Valid values:</p>
    /// <ul>
    /// <li>
    /// <p><code>manual</code> - The action requires you to resolve the recommendation manually.</p></li>
    /// <li>
    /// <p><code>immediately</code> - The action is applied immediately.</p></li>
    /// <li>
    /// <p><code>next-maintainance-window</code> - The action is applied during the next scheduled maintainance.</p></li>
    /// </ul>
    pub fn apply_modes(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.apply_modes.unwrap_or_default();
        v.push(input.into());
        self.apply_modes = ::std::option::Option::Some(v);
        self
    }
    /// <p>The methods to apply the recommended action.</p>
    /// <p>Valid values:</p>
    /// <ul>
    /// <li>
    /// <p><code>manual</code> - The action requires you to resolve the recommendation manually.</p></li>
    /// <li>
    /// <p><code>immediately</code> - The action is applied immediately.</p></li>
    /// <li>
    /// <p><code>next-maintainance-window</code> - The action is applied during the next scheduled maintainance.</p></li>
    /// </ul>
    pub fn set_apply_modes(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.apply_modes = input;
        self
    }
    /// <p>The methods to apply the recommended action.</p>
    /// <p>Valid values:</p>
    /// <ul>
    /// <li>
    /// <p><code>manual</code> - The action requires you to resolve the recommendation manually.</p></li>
    /// <li>
    /// <p><code>immediately</code> - The action is applied immediately.</p></li>
    /// <li>
    /// <p><code>next-maintainance-window</code> - The action is applied during the next scheduled maintainance.</p></li>
    /// </ul>
    pub fn get_apply_modes(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.apply_modes
    }
    /// <p>The status of the action.</p>
    /// <ul>
    /// <li>
    /// <p><code>ready</code></p></li>
    /// <li>
    /// <p><code>applied</code></p></li>
    /// <li>
    /// <p><code>scheduled</code></p></li>
    /// <li>
    /// <p><code>resolved</code></p></li>
    /// </ul>
    pub fn status(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.status = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The status of the action.</p>
    /// <ul>
    /// <li>
    /// <p><code>ready</code></p></li>
    /// <li>
    /// <p><code>applied</code></p></li>
    /// <li>
    /// <p><code>scheduled</code></p></li>
    /// <li>
    /// <p><code>resolved</code></p></li>
    /// </ul>
    pub fn set_status(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.status = input;
        self
    }
    /// <p>The status of the action.</p>
    /// <ul>
    /// <li>
    /// <p><code>ready</code></p></li>
    /// <li>
    /// <p><code>applied</code></p></li>
    /// <li>
    /// <p><code>scheduled</code></p></li>
    /// <li>
    /// <p><code>resolved</code></p></li>
    /// </ul>
    pub fn get_status(&self) -> &::std::option::Option<::std::string::String> {
        &self.status
    }
    /// <p>The details of the issue.</p>
    pub fn issue_details(mut self, input: crate::types::IssueDetails) -> Self {
        self.issue_details = ::std::option::Option::Some(input);
        self
    }
    /// <p>The details of the issue.</p>
    pub fn set_issue_details(mut self, input: ::std::option::Option<crate::types::IssueDetails>) -> Self {
        self.issue_details = input;
        self
    }
    /// <p>The details of the issue.</p>
    pub fn get_issue_details(&self) -> &::std::option::Option<crate::types::IssueDetails> {
        &self.issue_details
    }
    /// Appends an item to `context_attributes`.
    ///
    /// To override the contents of this collection use [`set_context_attributes`](Self::set_context_attributes).
    ///
    /// <p>The supporting attributes to explain the recommended action.</p>
    pub fn context_attributes(mut self, input: crate::types::ContextAttribute) -> Self {
        let mut v = self.context_attributes.unwrap_or_default();
        v.push(input);
        self.context_attributes = ::std::option::Option::Some(v);
        self
    }
    /// <p>The supporting attributes to explain the recommended action.</p>
    pub fn set_context_attributes(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::ContextAttribute>>) -> Self {
        self.context_attributes = input;
        self
    }
    /// <p>The supporting attributes to explain the recommended action.</p>
    pub fn get_context_attributes(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::ContextAttribute>> {
        &self.context_attributes
    }
    /// Consumes the builder and constructs a [`RecommendedAction`](crate::types::RecommendedAction).
    pub fn build(self) -> crate::types::RecommendedAction {
        crate::types::RecommendedAction {
            action_id: self.action_id,
            title: self.title,
            description: self.description,
            operation: self.operation,
            parameters: self.parameters,
            apply_modes: self.apply_modes,
            status: self.status,
            issue_details: self.issue_details,
            context_attributes: self.context_attributes,
        }
    }
}
