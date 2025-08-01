// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The current configuration of all Kubernetes data sources for the organization.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct OrganizationKubernetesConfigurationResult {
    /// <p>The current configuration of Kubernetes audit logs as a data source for the organization.</p>
    pub audit_logs: ::std::option::Option<crate::types::OrganizationKubernetesAuditLogsConfigurationResult>,
}
impl OrganizationKubernetesConfigurationResult {
    /// <p>The current configuration of Kubernetes audit logs as a data source for the organization.</p>
    pub fn audit_logs(&self) -> ::std::option::Option<&crate::types::OrganizationKubernetesAuditLogsConfigurationResult> {
        self.audit_logs.as_ref()
    }
}
impl OrganizationKubernetesConfigurationResult {
    /// Creates a new builder-style object to manufacture [`OrganizationKubernetesConfigurationResult`](crate::types::OrganizationKubernetesConfigurationResult).
    pub fn builder() -> crate::types::builders::OrganizationKubernetesConfigurationResultBuilder {
        crate::types::builders::OrganizationKubernetesConfigurationResultBuilder::default()
    }
}

/// A builder for [`OrganizationKubernetesConfigurationResult`](crate::types::OrganizationKubernetesConfigurationResult).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct OrganizationKubernetesConfigurationResultBuilder {
    pub(crate) audit_logs: ::std::option::Option<crate::types::OrganizationKubernetesAuditLogsConfigurationResult>,
}
impl OrganizationKubernetesConfigurationResultBuilder {
    /// <p>The current configuration of Kubernetes audit logs as a data source for the organization.</p>
    /// This field is required.
    pub fn audit_logs(mut self, input: crate::types::OrganizationKubernetesAuditLogsConfigurationResult) -> Self {
        self.audit_logs = ::std::option::Option::Some(input);
        self
    }
    /// <p>The current configuration of Kubernetes audit logs as a data source for the organization.</p>
    pub fn set_audit_logs(mut self, input: ::std::option::Option<crate::types::OrganizationKubernetesAuditLogsConfigurationResult>) -> Self {
        self.audit_logs = input;
        self
    }
    /// <p>The current configuration of Kubernetes audit logs as a data source for the organization.</p>
    pub fn get_audit_logs(&self) -> &::std::option::Option<crate::types::OrganizationKubernetesAuditLogsConfigurationResult> {
        &self.audit_logs
    }
    /// Consumes the builder and constructs a [`OrganizationKubernetesConfigurationResult`](crate::types::OrganizationKubernetesConfigurationResult).
    pub fn build(self) -> crate::types::OrganizationKubernetesConfigurationResult {
        crate::types::OrganizationKubernetesConfigurationResult { audit_logs: self.audit_logs }
    }
}
