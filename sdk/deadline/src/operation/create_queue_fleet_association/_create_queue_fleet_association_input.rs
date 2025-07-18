// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateQueueFleetAssociationInput {
    /// <p>The ID of the farm that the queue and fleet belong to.</p>
    pub farm_id: ::std::option::Option<::std::string::String>,
    /// <p>The queue ID.</p>
    pub queue_id: ::std::option::Option<::std::string::String>,
    /// <p>The fleet ID.</p>
    pub fleet_id: ::std::option::Option<::std::string::String>,
}
impl CreateQueueFleetAssociationInput {
    /// <p>The ID of the farm that the queue and fleet belong to.</p>
    pub fn farm_id(&self) -> ::std::option::Option<&str> {
        self.farm_id.as_deref()
    }
    /// <p>The queue ID.</p>
    pub fn queue_id(&self) -> ::std::option::Option<&str> {
        self.queue_id.as_deref()
    }
    /// <p>The fleet ID.</p>
    pub fn fleet_id(&self) -> ::std::option::Option<&str> {
        self.fleet_id.as_deref()
    }
}
impl CreateQueueFleetAssociationInput {
    /// Creates a new builder-style object to manufacture [`CreateQueueFleetAssociationInput`](crate::operation::create_queue_fleet_association::CreateQueueFleetAssociationInput).
    pub fn builder() -> crate::operation::create_queue_fleet_association::builders::CreateQueueFleetAssociationInputBuilder {
        crate::operation::create_queue_fleet_association::builders::CreateQueueFleetAssociationInputBuilder::default()
    }
}

/// A builder for [`CreateQueueFleetAssociationInput`](crate::operation::create_queue_fleet_association::CreateQueueFleetAssociationInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateQueueFleetAssociationInputBuilder {
    pub(crate) farm_id: ::std::option::Option<::std::string::String>,
    pub(crate) queue_id: ::std::option::Option<::std::string::String>,
    pub(crate) fleet_id: ::std::option::Option<::std::string::String>,
}
impl CreateQueueFleetAssociationInputBuilder {
    /// <p>The ID of the farm that the queue and fleet belong to.</p>
    /// This field is required.
    pub fn farm_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.farm_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the farm that the queue and fleet belong to.</p>
    pub fn set_farm_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.farm_id = input;
        self
    }
    /// <p>The ID of the farm that the queue and fleet belong to.</p>
    pub fn get_farm_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.farm_id
    }
    /// <p>The queue ID.</p>
    /// This field is required.
    pub fn queue_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.queue_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The queue ID.</p>
    pub fn set_queue_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.queue_id = input;
        self
    }
    /// <p>The queue ID.</p>
    pub fn get_queue_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.queue_id
    }
    /// <p>The fleet ID.</p>
    /// This field is required.
    pub fn fleet_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.fleet_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The fleet ID.</p>
    pub fn set_fleet_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.fleet_id = input;
        self
    }
    /// <p>The fleet ID.</p>
    pub fn get_fleet_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.fleet_id
    }
    /// Consumes the builder and constructs a [`CreateQueueFleetAssociationInput`](crate::operation::create_queue_fleet_association::CreateQueueFleetAssociationInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::create_queue_fleet_association::CreateQueueFleetAssociationInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::create_queue_fleet_association::CreateQueueFleetAssociationInput {
            farm_id: self.farm_id,
            queue_id: self.queue_id,
            fleet_id: self.fleet_id,
        })
    }
}
