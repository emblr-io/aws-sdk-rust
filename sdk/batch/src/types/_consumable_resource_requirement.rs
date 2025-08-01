// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Information about a consumable resource required to run a job.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ConsumableResourceRequirement {
    /// <p>The name or ARN of the consumable resource.</p>
    pub consumable_resource: ::std::option::Option<::std::string::String>,
    /// <p>The quantity of the consumable resource that is needed.</p>
    pub quantity: ::std::option::Option<i64>,
}
impl ConsumableResourceRequirement {
    /// <p>The name or ARN of the consumable resource.</p>
    pub fn consumable_resource(&self) -> ::std::option::Option<&str> {
        self.consumable_resource.as_deref()
    }
    /// <p>The quantity of the consumable resource that is needed.</p>
    pub fn quantity(&self) -> ::std::option::Option<i64> {
        self.quantity
    }
}
impl ConsumableResourceRequirement {
    /// Creates a new builder-style object to manufacture [`ConsumableResourceRequirement`](crate::types::ConsumableResourceRequirement).
    pub fn builder() -> crate::types::builders::ConsumableResourceRequirementBuilder {
        crate::types::builders::ConsumableResourceRequirementBuilder::default()
    }
}

/// A builder for [`ConsumableResourceRequirement`](crate::types::ConsumableResourceRequirement).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ConsumableResourceRequirementBuilder {
    pub(crate) consumable_resource: ::std::option::Option<::std::string::String>,
    pub(crate) quantity: ::std::option::Option<i64>,
}
impl ConsumableResourceRequirementBuilder {
    /// <p>The name or ARN of the consumable resource.</p>
    pub fn consumable_resource(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.consumable_resource = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name or ARN of the consumable resource.</p>
    pub fn set_consumable_resource(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.consumable_resource = input;
        self
    }
    /// <p>The name or ARN of the consumable resource.</p>
    pub fn get_consumable_resource(&self) -> &::std::option::Option<::std::string::String> {
        &self.consumable_resource
    }
    /// <p>The quantity of the consumable resource that is needed.</p>
    pub fn quantity(mut self, input: i64) -> Self {
        self.quantity = ::std::option::Option::Some(input);
        self
    }
    /// <p>The quantity of the consumable resource that is needed.</p>
    pub fn set_quantity(mut self, input: ::std::option::Option<i64>) -> Self {
        self.quantity = input;
        self
    }
    /// <p>The quantity of the consumable resource that is needed.</p>
    pub fn get_quantity(&self) -> &::std::option::Option<i64> {
        &self.quantity
    }
    /// Consumes the builder and constructs a [`ConsumableResourceRequirement`](crate::types::ConsumableResourceRequirement).
    pub fn build(self) -> crate::types::ConsumableResourceRequirement {
        crate::types::ConsumableResourceRequirement {
            consumable_resource: self.consumable_resource,
            quantity: self.quantity,
        }
    }
}
