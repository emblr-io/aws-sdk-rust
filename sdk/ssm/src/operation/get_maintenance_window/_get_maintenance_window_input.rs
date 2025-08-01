// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetMaintenanceWindowInput {
    /// <p>The ID of the maintenance window for which you want to retrieve information.</p>
    pub window_id: ::std::option::Option<::std::string::String>,
}
impl GetMaintenanceWindowInput {
    /// <p>The ID of the maintenance window for which you want to retrieve information.</p>
    pub fn window_id(&self) -> ::std::option::Option<&str> {
        self.window_id.as_deref()
    }
}
impl GetMaintenanceWindowInput {
    /// Creates a new builder-style object to manufacture [`GetMaintenanceWindowInput`](crate::operation::get_maintenance_window::GetMaintenanceWindowInput).
    pub fn builder() -> crate::operation::get_maintenance_window::builders::GetMaintenanceWindowInputBuilder {
        crate::operation::get_maintenance_window::builders::GetMaintenanceWindowInputBuilder::default()
    }
}

/// A builder for [`GetMaintenanceWindowInput`](crate::operation::get_maintenance_window::GetMaintenanceWindowInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetMaintenanceWindowInputBuilder {
    pub(crate) window_id: ::std::option::Option<::std::string::String>,
}
impl GetMaintenanceWindowInputBuilder {
    /// <p>The ID of the maintenance window for which you want to retrieve information.</p>
    /// This field is required.
    pub fn window_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.window_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the maintenance window for which you want to retrieve information.</p>
    pub fn set_window_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.window_id = input;
        self
    }
    /// <p>The ID of the maintenance window for which you want to retrieve information.</p>
    pub fn get_window_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.window_id
    }
    /// Consumes the builder and constructs a [`GetMaintenanceWindowInput`](crate::operation::get_maintenance_window::GetMaintenanceWindowInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::get_maintenance_window::GetMaintenanceWindowInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::get_maintenance_window::GetMaintenanceWindowInput { window_id: self.window_id })
    }
}
