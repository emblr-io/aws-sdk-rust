// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Determines whether or not hidden fields are visible on exported dashbaords.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ExportWithHiddenFieldsOption {
    /// <p>The status of the export with hidden fields options.</p>
    pub availability_status: ::std::option::Option<crate::types::DashboardBehavior>,
}
impl ExportWithHiddenFieldsOption {
    /// <p>The status of the export with hidden fields options.</p>
    pub fn availability_status(&self) -> ::std::option::Option<&crate::types::DashboardBehavior> {
        self.availability_status.as_ref()
    }
}
impl ExportWithHiddenFieldsOption {
    /// Creates a new builder-style object to manufacture [`ExportWithHiddenFieldsOption`](crate::types::ExportWithHiddenFieldsOption).
    pub fn builder() -> crate::types::builders::ExportWithHiddenFieldsOptionBuilder {
        crate::types::builders::ExportWithHiddenFieldsOptionBuilder::default()
    }
}

/// A builder for [`ExportWithHiddenFieldsOption`](crate::types::ExportWithHiddenFieldsOption).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ExportWithHiddenFieldsOptionBuilder {
    pub(crate) availability_status: ::std::option::Option<crate::types::DashboardBehavior>,
}
impl ExportWithHiddenFieldsOptionBuilder {
    /// <p>The status of the export with hidden fields options.</p>
    pub fn availability_status(mut self, input: crate::types::DashboardBehavior) -> Self {
        self.availability_status = ::std::option::Option::Some(input);
        self
    }
    /// <p>The status of the export with hidden fields options.</p>
    pub fn set_availability_status(mut self, input: ::std::option::Option<crate::types::DashboardBehavior>) -> Self {
        self.availability_status = input;
        self
    }
    /// <p>The status of the export with hidden fields options.</p>
    pub fn get_availability_status(&self) -> &::std::option::Option<crate::types::DashboardBehavior> {
        &self.availability_status
    }
    /// Consumes the builder and constructs a [`ExportWithHiddenFieldsOption`](crate::types::ExportWithHiddenFieldsOption).
    pub fn build(self) -> crate::types::ExportWithHiddenFieldsOption {
        crate::types::ExportWithHiddenFieldsOption {
            availability_status: self.availability_status,
        }
    }
}
