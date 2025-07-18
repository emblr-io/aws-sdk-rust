// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ExitStandbyInput {
    /// <p>The IDs of the instances. You can specify up to 20 instances.</p>
    pub instance_ids: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>The name of the Auto Scaling group.</p>
    pub auto_scaling_group_name: ::std::option::Option<::std::string::String>,
}
impl ExitStandbyInput {
    /// <p>The IDs of the instances. You can specify up to 20 instances.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.instance_ids.is_none()`.
    pub fn instance_ids(&self) -> &[::std::string::String] {
        self.instance_ids.as_deref().unwrap_or_default()
    }
    /// <p>The name of the Auto Scaling group.</p>
    pub fn auto_scaling_group_name(&self) -> ::std::option::Option<&str> {
        self.auto_scaling_group_name.as_deref()
    }
}
impl ExitStandbyInput {
    /// Creates a new builder-style object to manufacture [`ExitStandbyInput`](crate::operation::exit_standby::ExitStandbyInput).
    pub fn builder() -> crate::operation::exit_standby::builders::ExitStandbyInputBuilder {
        crate::operation::exit_standby::builders::ExitStandbyInputBuilder::default()
    }
}

/// A builder for [`ExitStandbyInput`](crate::operation::exit_standby::ExitStandbyInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ExitStandbyInputBuilder {
    pub(crate) instance_ids: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) auto_scaling_group_name: ::std::option::Option<::std::string::String>,
}
impl ExitStandbyInputBuilder {
    /// Appends an item to `instance_ids`.
    ///
    /// To override the contents of this collection use [`set_instance_ids`](Self::set_instance_ids).
    ///
    /// <p>The IDs of the instances. You can specify up to 20 instances.</p>
    pub fn instance_ids(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.instance_ids.unwrap_or_default();
        v.push(input.into());
        self.instance_ids = ::std::option::Option::Some(v);
        self
    }
    /// <p>The IDs of the instances. You can specify up to 20 instances.</p>
    pub fn set_instance_ids(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.instance_ids = input;
        self
    }
    /// <p>The IDs of the instances. You can specify up to 20 instances.</p>
    pub fn get_instance_ids(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.instance_ids
    }
    /// <p>The name of the Auto Scaling group.</p>
    /// This field is required.
    pub fn auto_scaling_group_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.auto_scaling_group_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the Auto Scaling group.</p>
    pub fn set_auto_scaling_group_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.auto_scaling_group_name = input;
        self
    }
    /// <p>The name of the Auto Scaling group.</p>
    pub fn get_auto_scaling_group_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.auto_scaling_group_name
    }
    /// Consumes the builder and constructs a [`ExitStandbyInput`](crate::operation::exit_standby::ExitStandbyInput).
    pub fn build(self) -> ::std::result::Result<crate::operation::exit_standby::ExitStandbyInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::exit_standby::ExitStandbyInput {
            instance_ids: self.instance_ids,
            auto_scaling_group_name: self.auto_scaling_group_name,
        })
    }
}
