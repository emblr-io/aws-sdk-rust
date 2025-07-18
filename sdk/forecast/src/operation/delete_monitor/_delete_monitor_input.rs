// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteMonitorInput {
    /// <p>The Amazon Resource Name (ARN) of the monitor resource to delete.</p>
    pub monitor_arn: ::std::option::Option<::std::string::String>,
}
impl DeleteMonitorInput {
    /// <p>The Amazon Resource Name (ARN) of the monitor resource to delete.</p>
    pub fn monitor_arn(&self) -> ::std::option::Option<&str> {
        self.monitor_arn.as_deref()
    }
}
impl DeleteMonitorInput {
    /// Creates a new builder-style object to manufacture [`DeleteMonitorInput`](crate::operation::delete_monitor::DeleteMonitorInput).
    pub fn builder() -> crate::operation::delete_monitor::builders::DeleteMonitorInputBuilder {
        crate::operation::delete_monitor::builders::DeleteMonitorInputBuilder::default()
    }
}

/// A builder for [`DeleteMonitorInput`](crate::operation::delete_monitor::DeleteMonitorInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeleteMonitorInputBuilder {
    pub(crate) monitor_arn: ::std::option::Option<::std::string::String>,
}
impl DeleteMonitorInputBuilder {
    /// <p>The Amazon Resource Name (ARN) of the monitor resource to delete.</p>
    /// This field is required.
    pub fn monitor_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.monitor_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the monitor resource to delete.</p>
    pub fn set_monitor_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.monitor_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the monitor resource to delete.</p>
    pub fn get_monitor_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.monitor_arn
    }
    /// Consumes the builder and constructs a [`DeleteMonitorInput`](crate::operation::delete_monitor::DeleteMonitorInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::delete_monitor::DeleteMonitorInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::delete_monitor::DeleteMonitorInput {
            monitor_arn: self.monitor_arn,
        })
    }
}
