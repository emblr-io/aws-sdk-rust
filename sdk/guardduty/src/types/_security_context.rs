// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Container security context.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct SecurityContext {
    /// <p>Whether the container is privileged.</p>
    pub privileged: ::std::option::Option<bool>,
    /// <p>Whether or not a container or a Kubernetes pod is allowed to gain more privileges than its parent process.</p>
    pub allow_privilege_escalation: ::std::option::Option<bool>,
}
impl SecurityContext {
    /// <p>Whether the container is privileged.</p>
    pub fn privileged(&self) -> ::std::option::Option<bool> {
        self.privileged
    }
    /// <p>Whether or not a container or a Kubernetes pod is allowed to gain more privileges than its parent process.</p>
    pub fn allow_privilege_escalation(&self) -> ::std::option::Option<bool> {
        self.allow_privilege_escalation
    }
}
impl SecurityContext {
    /// Creates a new builder-style object to manufacture [`SecurityContext`](crate::types::SecurityContext).
    pub fn builder() -> crate::types::builders::SecurityContextBuilder {
        crate::types::builders::SecurityContextBuilder::default()
    }
}

/// A builder for [`SecurityContext`](crate::types::SecurityContext).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct SecurityContextBuilder {
    pub(crate) privileged: ::std::option::Option<bool>,
    pub(crate) allow_privilege_escalation: ::std::option::Option<bool>,
}
impl SecurityContextBuilder {
    /// <p>Whether the container is privileged.</p>
    pub fn privileged(mut self, input: bool) -> Self {
        self.privileged = ::std::option::Option::Some(input);
        self
    }
    /// <p>Whether the container is privileged.</p>
    pub fn set_privileged(mut self, input: ::std::option::Option<bool>) -> Self {
        self.privileged = input;
        self
    }
    /// <p>Whether the container is privileged.</p>
    pub fn get_privileged(&self) -> &::std::option::Option<bool> {
        &self.privileged
    }
    /// <p>Whether or not a container or a Kubernetes pod is allowed to gain more privileges than its parent process.</p>
    pub fn allow_privilege_escalation(mut self, input: bool) -> Self {
        self.allow_privilege_escalation = ::std::option::Option::Some(input);
        self
    }
    /// <p>Whether or not a container or a Kubernetes pod is allowed to gain more privileges than its parent process.</p>
    pub fn set_allow_privilege_escalation(mut self, input: ::std::option::Option<bool>) -> Self {
        self.allow_privilege_escalation = input;
        self
    }
    /// <p>Whether or not a container or a Kubernetes pod is allowed to gain more privileges than its parent process.</p>
    pub fn get_allow_privilege_escalation(&self) -> &::std::option::Option<bool> {
        &self.allow_privilege_escalation
    }
    /// Consumes the builder and constructs a [`SecurityContext`](crate::types::SecurityContext).
    pub fn build(self) -> crate::types::SecurityContext {
        crate::types::SecurityContext {
            privileged: self.privileged,
            allow_privilege_escalation: self.allow_privilege_escalation,
        }
    }
}
