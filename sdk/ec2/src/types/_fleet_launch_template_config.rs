// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Describes a launch template and overrides.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct FleetLaunchTemplateConfig {
    /// <p>The launch template.</p>
    pub launch_template_specification: ::std::option::Option<crate::types::FleetLaunchTemplateSpecification>,
    /// <p>Any parameters that you specify override the same parameters in the launch template.</p>
    pub overrides: ::std::option::Option<::std::vec::Vec<crate::types::FleetLaunchTemplateOverrides>>,
}
impl FleetLaunchTemplateConfig {
    /// <p>The launch template.</p>
    pub fn launch_template_specification(&self) -> ::std::option::Option<&crate::types::FleetLaunchTemplateSpecification> {
        self.launch_template_specification.as_ref()
    }
    /// <p>Any parameters that you specify override the same parameters in the launch template.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.overrides.is_none()`.
    pub fn overrides(&self) -> &[crate::types::FleetLaunchTemplateOverrides] {
        self.overrides.as_deref().unwrap_or_default()
    }
}
impl FleetLaunchTemplateConfig {
    /// Creates a new builder-style object to manufacture [`FleetLaunchTemplateConfig`](crate::types::FleetLaunchTemplateConfig).
    pub fn builder() -> crate::types::builders::FleetLaunchTemplateConfigBuilder {
        crate::types::builders::FleetLaunchTemplateConfigBuilder::default()
    }
}

/// A builder for [`FleetLaunchTemplateConfig`](crate::types::FleetLaunchTemplateConfig).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct FleetLaunchTemplateConfigBuilder {
    pub(crate) launch_template_specification: ::std::option::Option<crate::types::FleetLaunchTemplateSpecification>,
    pub(crate) overrides: ::std::option::Option<::std::vec::Vec<crate::types::FleetLaunchTemplateOverrides>>,
}
impl FleetLaunchTemplateConfigBuilder {
    /// <p>The launch template.</p>
    pub fn launch_template_specification(mut self, input: crate::types::FleetLaunchTemplateSpecification) -> Self {
        self.launch_template_specification = ::std::option::Option::Some(input);
        self
    }
    /// <p>The launch template.</p>
    pub fn set_launch_template_specification(mut self, input: ::std::option::Option<crate::types::FleetLaunchTemplateSpecification>) -> Self {
        self.launch_template_specification = input;
        self
    }
    /// <p>The launch template.</p>
    pub fn get_launch_template_specification(&self) -> &::std::option::Option<crate::types::FleetLaunchTemplateSpecification> {
        &self.launch_template_specification
    }
    /// Appends an item to `overrides`.
    ///
    /// To override the contents of this collection use [`set_overrides`](Self::set_overrides).
    ///
    /// <p>Any parameters that you specify override the same parameters in the launch template.</p>
    pub fn overrides(mut self, input: crate::types::FleetLaunchTemplateOverrides) -> Self {
        let mut v = self.overrides.unwrap_or_default();
        v.push(input);
        self.overrides = ::std::option::Option::Some(v);
        self
    }
    /// <p>Any parameters that you specify override the same parameters in the launch template.</p>
    pub fn set_overrides(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::FleetLaunchTemplateOverrides>>) -> Self {
        self.overrides = input;
        self
    }
    /// <p>Any parameters that you specify override the same parameters in the launch template.</p>
    pub fn get_overrides(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::FleetLaunchTemplateOverrides>> {
        &self.overrides
    }
    /// Consumes the builder and constructs a [`FleetLaunchTemplateConfig`](crate::types::FleetLaunchTemplateConfig).
    pub fn build(self) -> crate::types::FleetLaunchTemplateConfig {
        crate::types::FleetLaunchTemplateConfig {
            launch_template_specification: self.launch_template_specification,
            overrides: self.overrides,
        }
    }
}
