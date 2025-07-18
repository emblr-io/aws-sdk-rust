// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The details of the policy grant.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateDomainUnitPolicyGrantDetail {
    /// <p>Specifies whether the policy grant is applied to child domain units.</p>
    pub include_child_domain_units: ::std::option::Option<bool>,
}
impl CreateDomainUnitPolicyGrantDetail {
    /// <p>Specifies whether the policy grant is applied to child domain units.</p>
    pub fn include_child_domain_units(&self) -> ::std::option::Option<bool> {
        self.include_child_domain_units
    }
}
impl CreateDomainUnitPolicyGrantDetail {
    /// Creates a new builder-style object to manufacture [`CreateDomainUnitPolicyGrantDetail`](crate::types::CreateDomainUnitPolicyGrantDetail).
    pub fn builder() -> crate::types::builders::CreateDomainUnitPolicyGrantDetailBuilder {
        crate::types::builders::CreateDomainUnitPolicyGrantDetailBuilder::default()
    }
}

/// A builder for [`CreateDomainUnitPolicyGrantDetail`](crate::types::CreateDomainUnitPolicyGrantDetail).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateDomainUnitPolicyGrantDetailBuilder {
    pub(crate) include_child_domain_units: ::std::option::Option<bool>,
}
impl CreateDomainUnitPolicyGrantDetailBuilder {
    /// <p>Specifies whether the policy grant is applied to child domain units.</p>
    pub fn include_child_domain_units(mut self, input: bool) -> Self {
        self.include_child_domain_units = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies whether the policy grant is applied to child domain units.</p>
    pub fn set_include_child_domain_units(mut self, input: ::std::option::Option<bool>) -> Self {
        self.include_child_domain_units = input;
        self
    }
    /// <p>Specifies whether the policy grant is applied to child domain units.</p>
    pub fn get_include_child_domain_units(&self) -> &::std::option::Option<bool> {
        &self.include_child_domain_units
    }
    /// Consumes the builder and constructs a [`CreateDomainUnitPolicyGrantDetail`](crate::types::CreateDomainUnitPolicyGrantDetail).
    pub fn build(self) -> crate::types::CreateDomainUnitPolicyGrantDetail {
        crate::types::CreateDomainUnitPolicyGrantDetail {
            include_child_domain_units: self.include_child_domain_units,
        }
    }
}
