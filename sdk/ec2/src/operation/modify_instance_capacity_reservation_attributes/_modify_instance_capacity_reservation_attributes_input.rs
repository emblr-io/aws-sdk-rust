// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ModifyInstanceCapacityReservationAttributesInput {
    /// <p>The ID of the instance to be modified.</p>
    pub instance_id: ::std::option::Option<::std::string::String>,
    /// <p>Information about the Capacity Reservation targeting option.</p>
    pub capacity_reservation_specification: ::std::option::Option<crate::types::CapacityReservationSpecification>,
    /// <p>Checks whether you have the required permissions for the action, without actually making the request, and provides an error response. If you have the required permissions, the error response is <code>DryRunOperation</code>. Otherwise, it is <code>UnauthorizedOperation</code>.</p>
    pub dry_run: ::std::option::Option<bool>,
}
impl ModifyInstanceCapacityReservationAttributesInput {
    /// <p>The ID of the instance to be modified.</p>
    pub fn instance_id(&self) -> ::std::option::Option<&str> {
        self.instance_id.as_deref()
    }
    /// <p>Information about the Capacity Reservation targeting option.</p>
    pub fn capacity_reservation_specification(&self) -> ::std::option::Option<&crate::types::CapacityReservationSpecification> {
        self.capacity_reservation_specification.as_ref()
    }
    /// <p>Checks whether you have the required permissions for the action, without actually making the request, and provides an error response. If you have the required permissions, the error response is <code>DryRunOperation</code>. Otherwise, it is <code>UnauthorizedOperation</code>.</p>
    pub fn dry_run(&self) -> ::std::option::Option<bool> {
        self.dry_run
    }
}
impl ModifyInstanceCapacityReservationAttributesInput {
    /// Creates a new builder-style object to manufacture [`ModifyInstanceCapacityReservationAttributesInput`](crate::operation::modify_instance_capacity_reservation_attributes::ModifyInstanceCapacityReservationAttributesInput).
    pub fn builder(
    ) -> crate::operation::modify_instance_capacity_reservation_attributes::builders::ModifyInstanceCapacityReservationAttributesInputBuilder {
        crate::operation::modify_instance_capacity_reservation_attributes::builders::ModifyInstanceCapacityReservationAttributesInputBuilder::default(
        )
    }
}

/// A builder for [`ModifyInstanceCapacityReservationAttributesInput`](crate::operation::modify_instance_capacity_reservation_attributes::ModifyInstanceCapacityReservationAttributesInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ModifyInstanceCapacityReservationAttributesInputBuilder {
    pub(crate) instance_id: ::std::option::Option<::std::string::String>,
    pub(crate) capacity_reservation_specification: ::std::option::Option<crate::types::CapacityReservationSpecification>,
    pub(crate) dry_run: ::std::option::Option<bool>,
}
impl ModifyInstanceCapacityReservationAttributesInputBuilder {
    /// <p>The ID of the instance to be modified.</p>
    /// This field is required.
    pub fn instance_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.instance_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the instance to be modified.</p>
    pub fn set_instance_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.instance_id = input;
        self
    }
    /// <p>The ID of the instance to be modified.</p>
    pub fn get_instance_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.instance_id
    }
    /// <p>Information about the Capacity Reservation targeting option.</p>
    /// This field is required.
    pub fn capacity_reservation_specification(mut self, input: crate::types::CapacityReservationSpecification) -> Self {
        self.capacity_reservation_specification = ::std::option::Option::Some(input);
        self
    }
    /// <p>Information about the Capacity Reservation targeting option.</p>
    pub fn set_capacity_reservation_specification(mut self, input: ::std::option::Option<crate::types::CapacityReservationSpecification>) -> Self {
        self.capacity_reservation_specification = input;
        self
    }
    /// <p>Information about the Capacity Reservation targeting option.</p>
    pub fn get_capacity_reservation_specification(&self) -> &::std::option::Option<crate::types::CapacityReservationSpecification> {
        &self.capacity_reservation_specification
    }
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
    /// Consumes the builder and constructs a [`ModifyInstanceCapacityReservationAttributesInput`](crate::operation::modify_instance_capacity_reservation_attributes::ModifyInstanceCapacityReservationAttributesInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::modify_instance_capacity_reservation_attributes::ModifyInstanceCapacityReservationAttributesInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(
            crate::operation::modify_instance_capacity_reservation_attributes::ModifyInstanceCapacityReservationAttributesInput {
                instance_id: self.instance_id,
                capacity_reservation_specification: self.capacity_reservation_specification,
                dry_run: self.dry_run,
            },
        )
    }
}
