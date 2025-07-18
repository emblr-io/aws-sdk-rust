// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UpdateQueueFleetAssociationInput {
    /// <p>The farm ID to update.</p>
    pub farm_id: ::std::option::Option<::std::string::String>,
    /// <p>The queue ID to update.</p>
    pub queue_id: ::std::option::Option<::std::string::String>,
    /// <p>The fleet ID to update.</p>
    pub fleet_id: ::std::option::Option<::std::string::String>,
    /// <p>The status to update.</p>
    pub status: ::std::option::Option<crate::types::UpdateQueueFleetAssociationStatus>,
}
impl UpdateQueueFleetAssociationInput {
    /// <p>The farm ID to update.</p>
    pub fn farm_id(&self) -> ::std::option::Option<&str> {
        self.farm_id.as_deref()
    }
    /// <p>The queue ID to update.</p>
    pub fn queue_id(&self) -> ::std::option::Option<&str> {
        self.queue_id.as_deref()
    }
    /// <p>The fleet ID to update.</p>
    pub fn fleet_id(&self) -> ::std::option::Option<&str> {
        self.fleet_id.as_deref()
    }
    /// <p>The status to update.</p>
    pub fn status(&self) -> ::std::option::Option<&crate::types::UpdateQueueFleetAssociationStatus> {
        self.status.as_ref()
    }
}
impl UpdateQueueFleetAssociationInput {
    /// Creates a new builder-style object to manufacture [`UpdateQueueFleetAssociationInput`](crate::operation::update_queue_fleet_association::UpdateQueueFleetAssociationInput).
    pub fn builder() -> crate::operation::update_queue_fleet_association::builders::UpdateQueueFleetAssociationInputBuilder {
        crate::operation::update_queue_fleet_association::builders::UpdateQueueFleetAssociationInputBuilder::default()
    }
}

/// A builder for [`UpdateQueueFleetAssociationInput`](crate::operation::update_queue_fleet_association::UpdateQueueFleetAssociationInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UpdateQueueFleetAssociationInputBuilder {
    pub(crate) farm_id: ::std::option::Option<::std::string::String>,
    pub(crate) queue_id: ::std::option::Option<::std::string::String>,
    pub(crate) fleet_id: ::std::option::Option<::std::string::String>,
    pub(crate) status: ::std::option::Option<crate::types::UpdateQueueFleetAssociationStatus>,
}
impl UpdateQueueFleetAssociationInputBuilder {
    /// <p>The farm ID to update.</p>
    /// This field is required.
    pub fn farm_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.farm_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The farm ID to update.</p>
    pub fn set_farm_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.farm_id = input;
        self
    }
    /// <p>The farm ID to update.</p>
    pub fn get_farm_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.farm_id
    }
    /// <p>The queue ID to update.</p>
    /// This field is required.
    pub fn queue_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.queue_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The queue ID to update.</p>
    pub fn set_queue_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.queue_id = input;
        self
    }
    /// <p>The queue ID to update.</p>
    pub fn get_queue_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.queue_id
    }
    /// <p>The fleet ID to update.</p>
    /// This field is required.
    pub fn fleet_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.fleet_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The fleet ID to update.</p>
    pub fn set_fleet_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.fleet_id = input;
        self
    }
    /// <p>The fleet ID to update.</p>
    pub fn get_fleet_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.fleet_id
    }
    /// <p>The status to update.</p>
    /// This field is required.
    pub fn status(mut self, input: crate::types::UpdateQueueFleetAssociationStatus) -> Self {
        self.status = ::std::option::Option::Some(input);
        self
    }
    /// <p>The status to update.</p>
    pub fn set_status(mut self, input: ::std::option::Option<crate::types::UpdateQueueFleetAssociationStatus>) -> Self {
        self.status = input;
        self
    }
    /// <p>The status to update.</p>
    pub fn get_status(&self) -> &::std::option::Option<crate::types::UpdateQueueFleetAssociationStatus> {
        &self.status
    }
    /// Consumes the builder and constructs a [`UpdateQueueFleetAssociationInput`](crate::operation::update_queue_fleet_association::UpdateQueueFleetAssociationInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::update_queue_fleet_association::UpdateQueueFleetAssociationInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::update_queue_fleet_association::UpdateQueueFleetAssociationInput {
            farm_id: self.farm_id,
            queue_id: self.queue_id,
            fleet_id: self.fleet_id,
            status: self.status,
        })
    }
}
