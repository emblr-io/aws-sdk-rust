// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Contains information about the effect that Organizations has on a policy simulation.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct OrganizationsDecisionDetail {
    /// <p>Specifies whether the simulated operation is allowed by the Organizations service control policies that impact the simulated user's account.</p>
    pub allowed_by_organizations: bool,
}
impl OrganizationsDecisionDetail {
    /// <p>Specifies whether the simulated operation is allowed by the Organizations service control policies that impact the simulated user's account.</p>
    pub fn allowed_by_organizations(&self) -> bool {
        self.allowed_by_organizations
    }
}
impl OrganizationsDecisionDetail {
    /// Creates a new builder-style object to manufacture [`OrganizationsDecisionDetail`](crate::types::OrganizationsDecisionDetail).
    pub fn builder() -> crate::types::builders::OrganizationsDecisionDetailBuilder {
        crate::types::builders::OrganizationsDecisionDetailBuilder::default()
    }
}

/// A builder for [`OrganizationsDecisionDetail`](crate::types::OrganizationsDecisionDetail).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct OrganizationsDecisionDetailBuilder {
    pub(crate) allowed_by_organizations: ::std::option::Option<bool>,
}
impl OrganizationsDecisionDetailBuilder {
    /// <p>Specifies whether the simulated operation is allowed by the Organizations service control policies that impact the simulated user's account.</p>
    pub fn allowed_by_organizations(mut self, input: bool) -> Self {
        self.allowed_by_organizations = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies whether the simulated operation is allowed by the Organizations service control policies that impact the simulated user's account.</p>
    pub fn set_allowed_by_organizations(mut self, input: ::std::option::Option<bool>) -> Self {
        self.allowed_by_organizations = input;
        self
    }
    /// <p>Specifies whether the simulated operation is allowed by the Organizations service control policies that impact the simulated user's account.</p>
    pub fn get_allowed_by_organizations(&self) -> &::std::option::Option<bool> {
        &self.allowed_by_organizations
    }
    /// Consumes the builder and constructs a [`OrganizationsDecisionDetail`](crate::types::OrganizationsDecisionDetail).
    pub fn build(self) -> crate::types::OrganizationsDecisionDetail {
        crate::types::OrganizationsDecisionDetail {
            allowed_by_organizations: self.allowed_by_organizations.unwrap_or_default(),
        }
    }
}
