// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CancelInstanceRefreshInput {
    /// <p>The name of the Auto Scaling group.</p>
    pub auto_scaling_group_name: ::std::option::Option<::std::string::String>,
}
impl CancelInstanceRefreshInput {
    /// <p>The name of the Auto Scaling group.</p>
    pub fn auto_scaling_group_name(&self) -> ::std::option::Option<&str> {
        self.auto_scaling_group_name.as_deref()
    }
}
impl CancelInstanceRefreshInput {
    /// Creates a new builder-style object to manufacture [`CancelInstanceRefreshInput`](crate::operation::cancel_instance_refresh::CancelInstanceRefreshInput).
    pub fn builder() -> crate::operation::cancel_instance_refresh::builders::CancelInstanceRefreshInputBuilder {
        crate::operation::cancel_instance_refresh::builders::CancelInstanceRefreshInputBuilder::default()
    }
}

/// A builder for [`CancelInstanceRefreshInput`](crate::operation::cancel_instance_refresh::CancelInstanceRefreshInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CancelInstanceRefreshInputBuilder {
    pub(crate) auto_scaling_group_name: ::std::option::Option<::std::string::String>,
}
impl CancelInstanceRefreshInputBuilder {
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
    /// Consumes the builder and constructs a [`CancelInstanceRefreshInput`](crate::operation::cancel_instance_refresh::CancelInstanceRefreshInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::cancel_instance_refresh::CancelInstanceRefreshInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::cancel_instance_refresh::CancelInstanceRefreshInput {
            auto_scaling_group_name: self.auto_scaling_group_name,
        })
    }
}
