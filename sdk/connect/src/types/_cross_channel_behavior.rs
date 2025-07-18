// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Defines the cross-channel routing behavior that allows an agent working on a contact in one channel to be offered a contact from a different channel.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CrossChannelBehavior {
    /// <p>Specifies the other channels that can be routed to an agent handling their current channel.</p>
    pub behavior_type: crate::types::BehaviorType,
}
impl CrossChannelBehavior {
    /// <p>Specifies the other channels that can be routed to an agent handling their current channel.</p>
    pub fn behavior_type(&self) -> &crate::types::BehaviorType {
        &self.behavior_type
    }
}
impl CrossChannelBehavior {
    /// Creates a new builder-style object to manufacture [`CrossChannelBehavior`](crate::types::CrossChannelBehavior).
    pub fn builder() -> crate::types::builders::CrossChannelBehaviorBuilder {
        crate::types::builders::CrossChannelBehaviorBuilder::default()
    }
}

/// A builder for [`CrossChannelBehavior`](crate::types::CrossChannelBehavior).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CrossChannelBehaviorBuilder {
    pub(crate) behavior_type: ::std::option::Option<crate::types::BehaviorType>,
}
impl CrossChannelBehaviorBuilder {
    /// <p>Specifies the other channels that can be routed to an agent handling their current channel.</p>
    /// This field is required.
    pub fn behavior_type(mut self, input: crate::types::BehaviorType) -> Self {
        self.behavior_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies the other channels that can be routed to an agent handling their current channel.</p>
    pub fn set_behavior_type(mut self, input: ::std::option::Option<crate::types::BehaviorType>) -> Self {
        self.behavior_type = input;
        self
    }
    /// <p>Specifies the other channels that can be routed to an agent handling their current channel.</p>
    pub fn get_behavior_type(&self) -> &::std::option::Option<crate::types::BehaviorType> {
        &self.behavior_type
    }
    /// Consumes the builder and constructs a [`CrossChannelBehavior`](crate::types::CrossChannelBehavior).
    /// This method will fail if any of the following fields are not set:
    /// - [`behavior_type`](crate::types::builders::CrossChannelBehaviorBuilder::behavior_type)
    pub fn build(self) -> ::std::result::Result<crate::types::CrossChannelBehavior, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::CrossChannelBehavior {
            behavior_type: self.behavior_type.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "behavior_type",
                    "behavior_type was not specified but it is required when building CrossChannelBehavior",
                )
            })?,
        })
    }
}
