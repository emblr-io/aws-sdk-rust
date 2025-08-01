// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The target for the domain unit.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DomainUnitTarget {
    /// <p>The ID of the domain unit.</p>
    pub domain_unit_id: ::std::string::String,
    /// <p>Specifies whether to apply a rule to the child domain units.</p>
    pub include_child_domain_units: ::std::option::Option<bool>,
}
impl DomainUnitTarget {
    /// <p>The ID of the domain unit.</p>
    pub fn domain_unit_id(&self) -> &str {
        use std::ops::Deref;
        self.domain_unit_id.deref()
    }
    /// <p>Specifies whether to apply a rule to the child domain units.</p>
    pub fn include_child_domain_units(&self) -> ::std::option::Option<bool> {
        self.include_child_domain_units
    }
}
impl DomainUnitTarget {
    /// Creates a new builder-style object to manufacture [`DomainUnitTarget`](crate::types::DomainUnitTarget).
    pub fn builder() -> crate::types::builders::DomainUnitTargetBuilder {
        crate::types::builders::DomainUnitTargetBuilder::default()
    }
}

/// A builder for [`DomainUnitTarget`](crate::types::DomainUnitTarget).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DomainUnitTargetBuilder {
    pub(crate) domain_unit_id: ::std::option::Option<::std::string::String>,
    pub(crate) include_child_domain_units: ::std::option::Option<bool>,
}
impl DomainUnitTargetBuilder {
    /// <p>The ID of the domain unit.</p>
    /// This field is required.
    pub fn domain_unit_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.domain_unit_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the domain unit.</p>
    pub fn set_domain_unit_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.domain_unit_id = input;
        self
    }
    /// <p>The ID of the domain unit.</p>
    pub fn get_domain_unit_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.domain_unit_id
    }
    /// <p>Specifies whether to apply a rule to the child domain units.</p>
    pub fn include_child_domain_units(mut self, input: bool) -> Self {
        self.include_child_domain_units = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies whether to apply a rule to the child domain units.</p>
    pub fn set_include_child_domain_units(mut self, input: ::std::option::Option<bool>) -> Self {
        self.include_child_domain_units = input;
        self
    }
    /// <p>Specifies whether to apply a rule to the child domain units.</p>
    pub fn get_include_child_domain_units(&self) -> &::std::option::Option<bool> {
        &self.include_child_domain_units
    }
    /// Consumes the builder and constructs a [`DomainUnitTarget`](crate::types::DomainUnitTarget).
    /// This method will fail if any of the following fields are not set:
    /// - [`domain_unit_id`](crate::types::builders::DomainUnitTargetBuilder::domain_unit_id)
    pub fn build(self) -> ::std::result::Result<crate::types::DomainUnitTarget, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::DomainUnitTarget {
            domain_unit_id: self.domain_unit_id.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "domain_unit_id",
                    "domain_unit_id was not specified but it is required when building DomainUnitTarget",
                )
            })?,
            include_child_domain_units: self.include_child_domain_units,
        })
    }
}
