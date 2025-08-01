// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ModifyInstanceEventStartTimeInput {
    /// <p>Checks whether you have the required permissions for the operation, without actually making the request, and provides an error response. If you have the required permissions, the error response is <code>DryRunOperation</code>. Otherwise, it is <code>UnauthorizedOperation</code>.</p>
    pub dry_run: ::std::option::Option<bool>,
    /// <p>The ID of the instance with the scheduled event.</p>
    pub instance_id: ::std::option::Option<::std::string::String>,
    /// <p>The ID of the event whose date and time you are modifying.</p>
    pub instance_event_id: ::std::option::Option<::std::string::String>,
    /// <p>The new date and time when the event will take place.</p>
    pub not_before: ::std::option::Option<::aws_smithy_types::DateTime>,
}
impl ModifyInstanceEventStartTimeInput {
    /// <p>Checks whether you have the required permissions for the operation, without actually making the request, and provides an error response. If you have the required permissions, the error response is <code>DryRunOperation</code>. Otherwise, it is <code>UnauthorizedOperation</code>.</p>
    pub fn dry_run(&self) -> ::std::option::Option<bool> {
        self.dry_run
    }
    /// <p>The ID of the instance with the scheduled event.</p>
    pub fn instance_id(&self) -> ::std::option::Option<&str> {
        self.instance_id.as_deref()
    }
    /// <p>The ID of the event whose date and time you are modifying.</p>
    pub fn instance_event_id(&self) -> ::std::option::Option<&str> {
        self.instance_event_id.as_deref()
    }
    /// <p>The new date and time when the event will take place.</p>
    pub fn not_before(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.not_before.as_ref()
    }
}
impl ModifyInstanceEventStartTimeInput {
    /// Creates a new builder-style object to manufacture [`ModifyInstanceEventStartTimeInput`](crate::operation::modify_instance_event_start_time::ModifyInstanceEventStartTimeInput).
    pub fn builder() -> crate::operation::modify_instance_event_start_time::builders::ModifyInstanceEventStartTimeInputBuilder {
        crate::operation::modify_instance_event_start_time::builders::ModifyInstanceEventStartTimeInputBuilder::default()
    }
}

/// A builder for [`ModifyInstanceEventStartTimeInput`](crate::operation::modify_instance_event_start_time::ModifyInstanceEventStartTimeInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ModifyInstanceEventStartTimeInputBuilder {
    pub(crate) dry_run: ::std::option::Option<bool>,
    pub(crate) instance_id: ::std::option::Option<::std::string::String>,
    pub(crate) instance_event_id: ::std::option::Option<::std::string::String>,
    pub(crate) not_before: ::std::option::Option<::aws_smithy_types::DateTime>,
}
impl ModifyInstanceEventStartTimeInputBuilder {
    /// <p>Checks whether you have the required permissions for the operation, without actually making the request, and provides an error response. If you have the required permissions, the error response is <code>DryRunOperation</code>. Otherwise, it is <code>UnauthorizedOperation</code>.</p>
    pub fn dry_run(mut self, input: bool) -> Self {
        self.dry_run = ::std::option::Option::Some(input);
        self
    }
    /// <p>Checks whether you have the required permissions for the operation, without actually making the request, and provides an error response. If you have the required permissions, the error response is <code>DryRunOperation</code>. Otherwise, it is <code>UnauthorizedOperation</code>.</p>
    pub fn set_dry_run(mut self, input: ::std::option::Option<bool>) -> Self {
        self.dry_run = input;
        self
    }
    /// <p>Checks whether you have the required permissions for the operation, without actually making the request, and provides an error response. If you have the required permissions, the error response is <code>DryRunOperation</code>. Otherwise, it is <code>UnauthorizedOperation</code>.</p>
    pub fn get_dry_run(&self) -> &::std::option::Option<bool> {
        &self.dry_run
    }
    /// <p>The ID of the instance with the scheduled event.</p>
    /// This field is required.
    pub fn instance_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.instance_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the instance with the scheduled event.</p>
    pub fn set_instance_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.instance_id = input;
        self
    }
    /// <p>The ID of the instance with the scheduled event.</p>
    pub fn get_instance_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.instance_id
    }
    /// <p>The ID of the event whose date and time you are modifying.</p>
    /// This field is required.
    pub fn instance_event_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.instance_event_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the event whose date and time you are modifying.</p>
    pub fn set_instance_event_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.instance_event_id = input;
        self
    }
    /// <p>The ID of the event whose date and time you are modifying.</p>
    pub fn get_instance_event_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.instance_event_id
    }
    /// <p>The new date and time when the event will take place.</p>
    /// This field is required.
    pub fn not_before(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.not_before = ::std::option::Option::Some(input);
        self
    }
    /// <p>The new date and time when the event will take place.</p>
    pub fn set_not_before(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.not_before = input;
        self
    }
    /// <p>The new date and time when the event will take place.</p>
    pub fn get_not_before(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.not_before
    }
    /// Consumes the builder and constructs a [`ModifyInstanceEventStartTimeInput`](crate::operation::modify_instance_event_start_time::ModifyInstanceEventStartTimeInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::modify_instance_event_start_time::ModifyInstanceEventStartTimeInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::modify_instance_event_start_time::ModifyInstanceEventStartTimeInput {
            dry_run: self.dry_run,
            instance_id: self.instance_id,
            instance_event_id: self.instance_event_id,
            not_before: self.not_before,
        })
    }
}
