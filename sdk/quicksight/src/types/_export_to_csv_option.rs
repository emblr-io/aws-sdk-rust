// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Export to .csv option.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ExportToCsvOption {
    /// <p>Availability status.</p>
    pub availability_status: ::std::option::Option<crate::types::DashboardBehavior>,
}
impl ExportToCsvOption {
    /// <p>Availability status.</p>
    pub fn availability_status(&self) -> ::std::option::Option<&crate::types::DashboardBehavior> {
        self.availability_status.as_ref()
    }
}
impl ExportToCsvOption {
    /// Creates a new builder-style object to manufacture [`ExportToCsvOption`](crate::types::ExportToCsvOption).
    pub fn builder() -> crate::types::builders::ExportToCsvOptionBuilder {
        crate::types::builders::ExportToCsvOptionBuilder::default()
    }
}

/// A builder for [`ExportToCsvOption`](crate::types::ExportToCsvOption).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ExportToCsvOptionBuilder {
    pub(crate) availability_status: ::std::option::Option<crate::types::DashboardBehavior>,
}
impl ExportToCsvOptionBuilder {
    /// <p>Availability status.</p>
    pub fn availability_status(mut self, input: crate::types::DashboardBehavior) -> Self {
        self.availability_status = ::std::option::Option::Some(input);
        self
    }
    /// <p>Availability status.</p>
    pub fn set_availability_status(mut self, input: ::std::option::Option<crate::types::DashboardBehavior>) -> Self {
        self.availability_status = input;
        self
    }
    /// <p>Availability status.</p>
    pub fn get_availability_status(&self) -> &::std::option::Option<crate::types::DashboardBehavior> {
        &self.availability_status
    }
    /// Consumes the builder and constructs a [`ExportToCsvOption`](crate::types::ExportToCsvOption).
    pub fn build(self) -> crate::types::ExportToCsvOption {
        crate::types::ExportToCsvOption {
            availability_status: self.availability_status,
        }
    }
}
