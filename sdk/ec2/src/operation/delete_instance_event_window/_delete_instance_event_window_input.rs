// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteInstanceEventWindowInput {
    /// <p>Checks whether you have the required permissions for the action, without actually making the request, and provides an error response. If you have the required permissions, the error response is <code>DryRunOperation</code>. Otherwise, it is <code>UnauthorizedOperation</code>.</p>
    pub dry_run: ::std::option::Option<bool>,
    /// <p>Specify <code>true</code> to force delete the event window. Use the force delete parameter if the event window is currently associated with targets.</p>
    pub force_delete: ::std::option::Option<bool>,
    /// <p>The ID of the event window.</p>
    pub instance_event_window_id: ::std::option::Option<::std::string::String>,
}
impl DeleteInstanceEventWindowInput {
    /// <p>Checks whether you have the required permissions for the action, without actually making the request, and provides an error response. If you have the required permissions, the error response is <code>DryRunOperation</code>. Otherwise, it is <code>UnauthorizedOperation</code>.</p>
    pub fn dry_run(&self) -> ::std::option::Option<bool> {
        self.dry_run
    }
    /// <p>Specify <code>true</code> to force delete the event window. Use the force delete parameter if the event window is currently associated with targets.</p>
    pub fn force_delete(&self) -> ::std::option::Option<bool> {
        self.force_delete
    }
    /// <p>The ID of the event window.</p>
    pub fn instance_event_window_id(&self) -> ::std::option::Option<&str> {
        self.instance_event_window_id.as_deref()
    }
}
impl DeleteInstanceEventWindowInput {
    /// Creates a new builder-style object to manufacture [`DeleteInstanceEventWindowInput`](crate::operation::delete_instance_event_window::DeleteInstanceEventWindowInput).
    pub fn builder() -> crate::operation::delete_instance_event_window::builders::DeleteInstanceEventWindowInputBuilder {
        crate::operation::delete_instance_event_window::builders::DeleteInstanceEventWindowInputBuilder::default()
    }
}

/// A builder for [`DeleteInstanceEventWindowInput`](crate::operation::delete_instance_event_window::DeleteInstanceEventWindowInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeleteInstanceEventWindowInputBuilder {
    pub(crate) dry_run: ::std::option::Option<bool>,
    pub(crate) force_delete: ::std::option::Option<bool>,
    pub(crate) instance_event_window_id: ::std::option::Option<::std::string::String>,
}
impl DeleteInstanceEventWindowInputBuilder {
    /// <p>Checks whether you have the required permissions for the action, without actually making the request, and provides an error response. If you have the required permissions, the error response is <code>DryRunOperation</code>. Otherwise, it is <code>UnauthorizedOperation</code>.</p>
    pub fn dry_run(mut self, input: bool) -> Self {
        self.dry_run = ::std::option::Option::Some(input);
        self
    }
    /// <p>Checks whether you have the required permissions for the action, without actually making the request, and provides an error response. If you have the required permissions, the error response is <code>DryRunOperation</code>. Otherwise, it is <code>UnauthorizedOperation</code>.</p>
    pub fn set_dry_run(mut self, input: ::std::option::Option<bool>) -> Self {
        self.dry_run = input;
        self
    }
    /// <p>Checks whether you have the required permissions for the action, without actually making the request, and provides an error response. If you have the required permissions, the error response is <code>DryRunOperation</code>. Otherwise, it is <code>UnauthorizedOperation</code>.</p>
    pub fn get_dry_run(&self) -> &::std::option::Option<bool> {
        &self.dry_run
    }
    /// <p>Specify <code>true</code> to force delete the event window. Use the force delete parameter if the event window is currently associated with targets.</p>
    pub fn force_delete(mut self, input: bool) -> Self {
        self.force_delete = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specify <code>true</code> to force delete the event window. Use the force delete parameter if the event window is currently associated with targets.</p>
    pub fn set_force_delete(mut self, input: ::std::option::Option<bool>) -> Self {
        self.force_delete = input;
        self
    }
    /// <p>Specify <code>true</code> to force delete the event window. Use the force delete parameter if the event window is currently associated with targets.</p>
    pub fn get_force_delete(&self) -> &::std::option::Option<bool> {
        &self.force_delete
    }
    /// <p>The ID of the event window.</p>
    /// This field is required.
    pub fn instance_event_window_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.instance_event_window_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the event window.</p>
    pub fn set_instance_event_window_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.instance_event_window_id = input;
        self
    }
    /// <p>The ID of the event window.</p>
    pub fn get_instance_event_window_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.instance_event_window_id
    }
    /// Consumes the builder and constructs a [`DeleteInstanceEventWindowInput`](crate::operation::delete_instance_event_window::DeleteInstanceEventWindowInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::delete_instance_event_window::DeleteInstanceEventWindowInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::delete_instance_event_window::DeleteInstanceEventWindowInput {
            dry_run: self.dry_run,
            force_delete: self.force_delete,
            instance_event_window_id: self.instance_event_window_id,
        })
    }
}
