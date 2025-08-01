// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UpdateCapacityProviderInput {
    /// <p>The name of the capacity provider to update.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>An object that represent the parameters to update for the Auto Scaling group capacity provider.</p>
    pub auto_scaling_group_provider: ::std::option::Option<crate::types::AutoScalingGroupProviderUpdate>,
}
impl UpdateCapacityProviderInput {
    /// <p>The name of the capacity provider to update.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>An object that represent the parameters to update for the Auto Scaling group capacity provider.</p>
    pub fn auto_scaling_group_provider(&self) -> ::std::option::Option<&crate::types::AutoScalingGroupProviderUpdate> {
        self.auto_scaling_group_provider.as_ref()
    }
}
impl UpdateCapacityProviderInput {
    /// Creates a new builder-style object to manufacture [`UpdateCapacityProviderInput`](crate::operation::update_capacity_provider::UpdateCapacityProviderInput).
    pub fn builder() -> crate::operation::update_capacity_provider::builders::UpdateCapacityProviderInputBuilder {
        crate::operation::update_capacity_provider::builders::UpdateCapacityProviderInputBuilder::default()
    }
}

/// A builder for [`UpdateCapacityProviderInput`](crate::operation::update_capacity_provider::UpdateCapacityProviderInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UpdateCapacityProviderInputBuilder {
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) auto_scaling_group_provider: ::std::option::Option<crate::types::AutoScalingGroupProviderUpdate>,
}
impl UpdateCapacityProviderInputBuilder {
    /// <p>The name of the capacity provider to update.</p>
    /// This field is required.
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the capacity provider to update.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the capacity provider to update.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>An object that represent the parameters to update for the Auto Scaling group capacity provider.</p>
    /// This field is required.
    pub fn auto_scaling_group_provider(mut self, input: crate::types::AutoScalingGroupProviderUpdate) -> Self {
        self.auto_scaling_group_provider = ::std::option::Option::Some(input);
        self
    }
    /// <p>An object that represent the parameters to update for the Auto Scaling group capacity provider.</p>
    pub fn set_auto_scaling_group_provider(mut self, input: ::std::option::Option<crate::types::AutoScalingGroupProviderUpdate>) -> Self {
        self.auto_scaling_group_provider = input;
        self
    }
    /// <p>An object that represent the parameters to update for the Auto Scaling group capacity provider.</p>
    pub fn get_auto_scaling_group_provider(&self) -> &::std::option::Option<crate::types::AutoScalingGroupProviderUpdate> {
        &self.auto_scaling_group_provider
    }
    /// Consumes the builder and constructs a [`UpdateCapacityProviderInput`](crate::operation::update_capacity_provider::UpdateCapacityProviderInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::update_capacity_provider::UpdateCapacityProviderInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::update_capacity_provider::UpdateCapacityProviderInput {
            name: self.name,
            auto_scaling_group_provider: self.auto_scaling_group_provider,
        })
    }
}
