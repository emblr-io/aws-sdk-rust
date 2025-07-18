// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Information about a deployment rollback.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct RollbackInfo {
    /// <p>The ID of the deployment rollback.</p>
    pub rollback_deployment_id: ::std::option::Option<::std::string::String>,
    /// <p>The deployment ID of the deployment that was underway and triggered a rollback deployment because it failed or was stopped.</p>
    pub rollback_triggering_deployment_id: ::std::option::Option<::std::string::String>,
    /// <p>Information that describes the status of a deployment rollback (for example, whether the deployment can't be rolled back, is in progress, failed, or succeeded).</p>
    pub rollback_message: ::std::option::Option<::std::string::String>,
}
impl RollbackInfo {
    /// <p>The ID of the deployment rollback.</p>
    pub fn rollback_deployment_id(&self) -> ::std::option::Option<&str> {
        self.rollback_deployment_id.as_deref()
    }
    /// <p>The deployment ID of the deployment that was underway and triggered a rollback deployment because it failed or was stopped.</p>
    pub fn rollback_triggering_deployment_id(&self) -> ::std::option::Option<&str> {
        self.rollback_triggering_deployment_id.as_deref()
    }
    /// <p>Information that describes the status of a deployment rollback (for example, whether the deployment can't be rolled back, is in progress, failed, or succeeded).</p>
    pub fn rollback_message(&self) -> ::std::option::Option<&str> {
        self.rollback_message.as_deref()
    }
}
impl RollbackInfo {
    /// Creates a new builder-style object to manufacture [`RollbackInfo`](crate::types::RollbackInfo).
    pub fn builder() -> crate::types::builders::RollbackInfoBuilder {
        crate::types::builders::RollbackInfoBuilder::default()
    }
}

/// A builder for [`RollbackInfo`](crate::types::RollbackInfo).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct RollbackInfoBuilder {
    pub(crate) rollback_deployment_id: ::std::option::Option<::std::string::String>,
    pub(crate) rollback_triggering_deployment_id: ::std::option::Option<::std::string::String>,
    pub(crate) rollback_message: ::std::option::Option<::std::string::String>,
}
impl RollbackInfoBuilder {
    /// <p>The ID of the deployment rollback.</p>
    pub fn rollback_deployment_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.rollback_deployment_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the deployment rollback.</p>
    pub fn set_rollback_deployment_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.rollback_deployment_id = input;
        self
    }
    /// <p>The ID of the deployment rollback.</p>
    pub fn get_rollback_deployment_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.rollback_deployment_id
    }
    /// <p>The deployment ID of the deployment that was underway and triggered a rollback deployment because it failed or was stopped.</p>
    pub fn rollback_triggering_deployment_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.rollback_triggering_deployment_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The deployment ID of the deployment that was underway and triggered a rollback deployment because it failed or was stopped.</p>
    pub fn set_rollback_triggering_deployment_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.rollback_triggering_deployment_id = input;
        self
    }
    /// <p>The deployment ID of the deployment that was underway and triggered a rollback deployment because it failed or was stopped.</p>
    pub fn get_rollback_triggering_deployment_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.rollback_triggering_deployment_id
    }
    /// <p>Information that describes the status of a deployment rollback (for example, whether the deployment can't be rolled back, is in progress, failed, or succeeded).</p>
    pub fn rollback_message(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.rollback_message = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Information that describes the status of a deployment rollback (for example, whether the deployment can't be rolled back, is in progress, failed, or succeeded).</p>
    pub fn set_rollback_message(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.rollback_message = input;
        self
    }
    /// <p>Information that describes the status of a deployment rollback (for example, whether the deployment can't be rolled back, is in progress, failed, or succeeded).</p>
    pub fn get_rollback_message(&self) -> &::std::option::Option<::std::string::String> {
        &self.rollback_message
    }
    /// Consumes the builder and constructs a [`RollbackInfo`](crate::types::RollbackInfo).
    pub fn build(self) -> crate::types::RollbackInfo {
        crate::types::RollbackInfo {
            rollback_deployment_id: self.rollback_deployment_id,
            rollback_triggering_deployment_id: self.rollback_triggering_deployment_id,
            rollback_message: self.rollback_message,
        }
    }
}
