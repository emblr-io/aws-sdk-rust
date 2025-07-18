// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The lifecycle policy action that was identified for the impacted resource.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct LifecycleExecutionResourceAction {
    /// <p>The name of the resource that was identified for a lifecycle policy action.</p>
    pub name: ::std::option::Option<crate::types::LifecycleExecutionResourceActionName>,
    /// <p>The reason why the lifecycle policy action is taken.</p>
    pub reason: ::std::option::Option<::std::string::String>,
}
impl LifecycleExecutionResourceAction {
    /// <p>The name of the resource that was identified for a lifecycle policy action.</p>
    pub fn name(&self) -> ::std::option::Option<&crate::types::LifecycleExecutionResourceActionName> {
        self.name.as_ref()
    }
    /// <p>The reason why the lifecycle policy action is taken.</p>
    pub fn reason(&self) -> ::std::option::Option<&str> {
        self.reason.as_deref()
    }
}
impl LifecycleExecutionResourceAction {
    /// Creates a new builder-style object to manufacture [`LifecycleExecutionResourceAction`](crate::types::LifecycleExecutionResourceAction).
    pub fn builder() -> crate::types::builders::LifecycleExecutionResourceActionBuilder {
        crate::types::builders::LifecycleExecutionResourceActionBuilder::default()
    }
}

/// A builder for [`LifecycleExecutionResourceAction`](crate::types::LifecycleExecutionResourceAction).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct LifecycleExecutionResourceActionBuilder {
    pub(crate) name: ::std::option::Option<crate::types::LifecycleExecutionResourceActionName>,
    pub(crate) reason: ::std::option::Option<::std::string::String>,
}
impl LifecycleExecutionResourceActionBuilder {
    /// <p>The name of the resource that was identified for a lifecycle policy action.</p>
    pub fn name(mut self, input: crate::types::LifecycleExecutionResourceActionName) -> Self {
        self.name = ::std::option::Option::Some(input);
        self
    }
    /// <p>The name of the resource that was identified for a lifecycle policy action.</p>
    pub fn set_name(mut self, input: ::std::option::Option<crate::types::LifecycleExecutionResourceActionName>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the resource that was identified for a lifecycle policy action.</p>
    pub fn get_name(&self) -> &::std::option::Option<crate::types::LifecycleExecutionResourceActionName> {
        &self.name
    }
    /// <p>The reason why the lifecycle policy action is taken.</p>
    pub fn reason(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.reason = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The reason why the lifecycle policy action is taken.</p>
    pub fn set_reason(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.reason = input;
        self
    }
    /// <p>The reason why the lifecycle policy action is taken.</p>
    pub fn get_reason(&self) -> &::std::option::Option<::std::string::String> {
        &self.reason
    }
    /// Consumes the builder and constructs a [`LifecycleExecutionResourceAction`](crate::types::LifecycleExecutionResourceAction).
    pub fn build(self) -> crate::types::LifecycleExecutionResourceAction {
        crate::types::LifecycleExecutionResourceAction {
            name: self.name,
            reason: self.reason,
        }
    }
}
