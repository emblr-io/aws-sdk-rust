// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The status of the compute fleet.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct FleetStatus {
    /// <p>The status code of the compute fleet. Valid values include:</p>
    /// <ul>
    /// <li>
    /// <p><code>CREATING</code>: The compute fleet is being created.</p></li>
    /// <li>
    /// <p><code>UPDATING</code>: The compute fleet is being updated.</p></li>
    /// <li>
    /// <p><code>ROTATING</code>: The compute fleet is being rotated.</p></li>
    /// <li>
    /// <p><code>PENDING_DELETION</code>: The compute fleet is pending deletion.</p></li>
    /// <li>
    /// <p><code>DELETING</code>: The compute fleet is being deleted.</p></li>
    /// <li>
    /// <p><code>CREATE_FAILED</code>: The compute fleet has failed to create.</p></li>
    /// <li>
    /// <p><code>UPDATE_ROLLBACK_FAILED</code>: The compute fleet has failed to update and could not rollback to previous state.</p></li>
    /// <li>
    /// <p><code>ACTIVE</code>: The compute fleet has succeeded and is active.</p></li>
    /// </ul>
    pub status_code: ::std::option::Option<crate::types::FleetStatusCode>,
    /// <p>Additional information about a compute fleet. Valid values include:</p>
    /// <ul>
    /// <li>
    /// <p><code>CREATE_FAILED</code>: The compute fleet has failed to create.</p></li>
    /// <li>
    /// <p><code>UPDATE_FAILED</code>: The compute fleet has failed to update.</p></li>
    /// </ul>
    pub context: ::std::option::Option<crate::types::FleetContextCode>,
    /// <p>A message associated with the status of a compute fleet.</p>
    pub message: ::std::option::Option<::std::string::String>,
}
impl FleetStatus {
    /// <p>The status code of the compute fleet. Valid values include:</p>
    /// <ul>
    /// <li>
    /// <p><code>CREATING</code>: The compute fleet is being created.</p></li>
    /// <li>
    /// <p><code>UPDATING</code>: The compute fleet is being updated.</p></li>
    /// <li>
    /// <p><code>ROTATING</code>: The compute fleet is being rotated.</p></li>
    /// <li>
    /// <p><code>PENDING_DELETION</code>: The compute fleet is pending deletion.</p></li>
    /// <li>
    /// <p><code>DELETING</code>: The compute fleet is being deleted.</p></li>
    /// <li>
    /// <p><code>CREATE_FAILED</code>: The compute fleet has failed to create.</p></li>
    /// <li>
    /// <p><code>UPDATE_ROLLBACK_FAILED</code>: The compute fleet has failed to update and could not rollback to previous state.</p></li>
    /// <li>
    /// <p><code>ACTIVE</code>: The compute fleet has succeeded and is active.</p></li>
    /// </ul>
    pub fn status_code(&self) -> ::std::option::Option<&crate::types::FleetStatusCode> {
        self.status_code.as_ref()
    }
    /// <p>Additional information about a compute fleet. Valid values include:</p>
    /// <ul>
    /// <li>
    /// <p><code>CREATE_FAILED</code>: The compute fleet has failed to create.</p></li>
    /// <li>
    /// <p><code>UPDATE_FAILED</code>: The compute fleet has failed to update.</p></li>
    /// </ul>
    pub fn context(&self) -> ::std::option::Option<&crate::types::FleetContextCode> {
        self.context.as_ref()
    }
    /// <p>A message associated with the status of a compute fleet.</p>
    pub fn message(&self) -> ::std::option::Option<&str> {
        self.message.as_deref()
    }
}
impl FleetStatus {
    /// Creates a new builder-style object to manufacture [`FleetStatus`](crate::types::FleetStatus).
    pub fn builder() -> crate::types::builders::FleetStatusBuilder {
        crate::types::builders::FleetStatusBuilder::default()
    }
}

/// A builder for [`FleetStatus`](crate::types::FleetStatus).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct FleetStatusBuilder {
    pub(crate) status_code: ::std::option::Option<crate::types::FleetStatusCode>,
    pub(crate) context: ::std::option::Option<crate::types::FleetContextCode>,
    pub(crate) message: ::std::option::Option<::std::string::String>,
}
impl FleetStatusBuilder {
    /// <p>The status code of the compute fleet. Valid values include:</p>
    /// <ul>
    /// <li>
    /// <p><code>CREATING</code>: The compute fleet is being created.</p></li>
    /// <li>
    /// <p><code>UPDATING</code>: The compute fleet is being updated.</p></li>
    /// <li>
    /// <p><code>ROTATING</code>: The compute fleet is being rotated.</p></li>
    /// <li>
    /// <p><code>PENDING_DELETION</code>: The compute fleet is pending deletion.</p></li>
    /// <li>
    /// <p><code>DELETING</code>: The compute fleet is being deleted.</p></li>
    /// <li>
    /// <p><code>CREATE_FAILED</code>: The compute fleet has failed to create.</p></li>
    /// <li>
    /// <p><code>UPDATE_ROLLBACK_FAILED</code>: The compute fleet has failed to update and could not rollback to previous state.</p></li>
    /// <li>
    /// <p><code>ACTIVE</code>: The compute fleet has succeeded and is active.</p></li>
    /// </ul>
    pub fn status_code(mut self, input: crate::types::FleetStatusCode) -> Self {
        self.status_code = ::std::option::Option::Some(input);
        self
    }
    /// <p>The status code of the compute fleet. Valid values include:</p>
    /// <ul>
    /// <li>
    /// <p><code>CREATING</code>: The compute fleet is being created.</p></li>
    /// <li>
    /// <p><code>UPDATING</code>: The compute fleet is being updated.</p></li>
    /// <li>
    /// <p><code>ROTATING</code>: The compute fleet is being rotated.</p></li>
    /// <li>
    /// <p><code>PENDING_DELETION</code>: The compute fleet is pending deletion.</p></li>
    /// <li>
    /// <p><code>DELETING</code>: The compute fleet is being deleted.</p></li>
    /// <li>
    /// <p><code>CREATE_FAILED</code>: The compute fleet has failed to create.</p></li>
    /// <li>
    /// <p><code>UPDATE_ROLLBACK_FAILED</code>: The compute fleet has failed to update and could not rollback to previous state.</p></li>
    /// <li>
    /// <p><code>ACTIVE</code>: The compute fleet has succeeded and is active.</p></li>
    /// </ul>
    pub fn set_status_code(mut self, input: ::std::option::Option<crate::types::FleetStatusCode>) -> Self {
        self.status_code = input;
        self
    }
    /// <p>The status code of the compute fleet. Valid values include:</p>
    /// <ul>
    /// <li>
    /// <p><code>CREATING</code>: The compute fleet is being created.</p></li>
    /// <li>
    /// <p><code>UPDATING</code>: The compute fleet is being updated.</p></li>
    /// <li>
    /// <p><code>ROTATING</code>: The compute fleet is being rotated.</p></li>
    /// <li>
    /// <p><code>PENDING_DELETION</code>: The compute fleet is pending deletion.</p></li>
    /// <li>
    /// <p><code>DELETING</code>: The compute fleet is being deleted.</p></li>
    /// <li>
    /// <p><code>CREATE_FAILED</code>: The compute fleet has failed to create.</p></li>
    /// <li>
    /// <p><code>UPDATE_ROLLBACK_FAILED</code>: The compute fleet has failed to update and could not rollback to previous state.</p></li>
    /// <li>
    /// <p><code>ACTIVE</code>: The compute fleet has succeeded and is active.</p></li>
    /// </ul>
    pub fn get_status_code(&self) -> &::std::option::Option<crate::types::FleetStatusCode> {
        &self.status_code
    }
    /// <p>Additional information about a compute fleet. Valid values include:</p>
    /// <ul>
    /// <li>
    /// <p><code>CREATE_FAILED</code>: The compute fleet has failed to create.</p></li>
    /// <li>
    /// <p><code>UPDATE_FAILED</code>: The compute fleet has failed to update.</p></li>
    /// </ul>
    pub fn context(mut self, input: crate::types::FleetContextCode) -> Self {
        self.context = ::std::option::Option::Some(input);
        self
    }
    /// <p>Additional information about a compute fleet. Valid values include:</p>
    /// <ul>
    /// <li>
    /// <p><code>CREATE_FAILED</code>: The compute fleet has failed to create.</p></li>
    /// <li>
    /// <p><code>UPDATE_FAILED</code>: The compute fleet has failed to update.</p></li>
    /// </ul>
    pub fn set_context(mut self, input: ::std::option::Option<crate::types::FleetContextCode>) -> Self {
        self.context = input;
        self
    }
    /// <p>Additional information about a compute fleet. Valid values include:</p>
    /// <ul>
    /// <li>
    /// <p><code>CREATE_FAILED</code>: The compute fleet has failed to create.</p></li>
    /// <li>
    /// <p><code>UPDATE_FAILED</code>: The compute fleet has failed to update.</p></li>
    /// </ul>
    pub fn get_context(&self) -> &::std::option::Option<crate::types::FleetContextCode> {
        &self.context
    }
    /// <p>A message associated with the status of a compute fleet.</p>
    pub fn message(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.message = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A message associated with the status of a compute fleet.</p>
    pub fn set_message(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.message = input;
        self
    }
    /// <p>A message associated with the status of a compute fleet.</p>
    pub fn get_message(&self) -> &::std::option::Option<::std::string::String> {
        &self.message
    }
    /// Consumes the builder and constructs a [`FleetStatus`](crate::types::FleetStatus).
    pub fn build(self) -> crate::types::FleetStatus {
        crate::types::FleetStatus {
            status_code: self.status_code,
            context: self.context,
            message: self.message,
        }
    }
}
