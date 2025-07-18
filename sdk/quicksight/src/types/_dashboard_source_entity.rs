// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Dashboard source entity.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DashboardSourceEntity {
    /// <p>Source template.</p>
    pub source_template: ::std::option::Option<crate::types::DashboardSourceTemplate>,
}
impl DashboardSourceEntity {
    /// <p>Source template.</p>
    pub fn source_template(&self) -> ::std::option::Option<&crate::types::DashboardSourceTemplate> {
        self.source_template.as_ref()
    }
}
impl DashboardSourceEntity {
    /// Creates a new builder-style object to manufacture [`DashboardSourceEntity`](crate::types::DashboardSourceEntity).
    pub fn builder() -> crate::types::builders::DashboardSourceEntityBuilder {
        crate::types::builders::DashboardSourceEntityBuilder::default()
    }
}

/// A builder for [`DashboardSourceEntity`](crate::types::DashboardSourceEntity).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DashboardSourceEntityBuilder {
    pub(crate) source_template: ::std::option::Option<crate::types::DashboardSourceTemplate>,
}
impl DashboardSourceEntityBuilder {
    /// <p>Source template.</p>
    pub fn source_template(mut self, input: crate::types::DashboardSourceTemplate) -> Self {
        self.source_template = ::std::option::Option::Some(input);
        self
    }
    /// <p>Source template.</p>
    pub fn set_source_template(mut self, input: ::std::option::Option<crate::types::DashboardSourceTemplate>) -> Self {
        self.source_template = input;
        self
    }
    /// <p>Source template.</p>
    pub fn get_source_template(&self) -> &::std::option::Option<crate::types::DashboardSourceTemplate> {
        &self.source_template
    }
    /// Consumes the builder and constructs a [`DashboardSourceEntity`](crate::types::DashboardSourceEntity).
    pub fn build(self) -> crate::types::DashboardSourceEntity {
        crate::types::DashboardSourceEntity {
            source_template: self.source_template,
        }
    }
}
