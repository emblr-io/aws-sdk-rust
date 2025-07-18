// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteMaintenanceWindowInput {
    /// <p>The ID of the maintenance window to delete.</p>
    pub window_id: ::std::option::Option<::std::string::String>,
}
impl DeleteMaintenanceWindowInput {
    /// <p>The ID of the maintenance window to delete.</p>
    pub fn window_id(&self) -> ::std::option::Option<&str> {
        self.window_id.as_deref()
    }
}
impl DeleteMaintenanceWindowInput {
    /// Creates a new builder-style object to manufacture [`DeleteMaintenanceWindowInput`](crate::operation::delete_maintenance_window::DeleteMaintenanceWindowInput).
    pub fn builder() -> crate::operation::delete_maintenance_window::builders::DeleteMaintenanceWindowInputBuilder {
        crate::operation::delete_maintenance_window::builders::DeleteMaintenanceWindowInputBuilder::default()
    }
}

/// A builder for [`DeleteMaintenanceWindowInput`](crate::operation::delete_maintenance_window::DeleteMaintenanceWindowInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeleteMaintenanceWindowInputBuilder {
    pub(crate) window_id: ::std::option::Option<::std::string::String>,
}
impl DeleteMaintenanceWindowInputBuilder {
    /// <p>The ID of the maintenance window to delete.</p>
    /// This field is required.
    pub fn window_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.window_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the maintenance window to delete.</p>
    pub fn set_window_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.window_id = input;
        self
    }
    /// <p>The ID of the maintenance window to delete.</p>
    pub fn get_window_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.window_id
    }
    /// Consumes the builder and constructs a [`DeleteMaintenanceWindowInput`](crate::operation::delete_maintenance_window::DeleteMaintenanceWindowInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::delete_maintenance_window::DeleteMaintenanceWindowInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::delete_maintenance_window::DeleteMaintenanceWindowInput { window_id: self.window_id })
    }
}
