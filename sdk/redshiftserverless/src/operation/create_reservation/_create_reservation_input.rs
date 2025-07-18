// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateReservationInput {
    /// <p>The number of Redshift Processing Units (RPUs) to reserve.</p>
    pub capacity: ::std::option::Option<i32>,
    /// <p>The ID of the offering associated with the reservation. The offering determines the payment schedule for the reservation.</p>
    pub offering_id: ::std::option::Option<::std::string::String>,
    /// <p>A unique, case-sensitive identifier that you provide to ensure the idempotency of the request. If not provided, the Amazon Web Services SDK populates this field. This token must be a valid UUIDv4 value. For more information about idempotency, see <a href="https://aws.amazon.com/builders-library/making-retries-safe-with-idempotent-APIs/"> Making retries safe with idempotent APIs </a>.</p>
    pub client_token: ::std::option::Option<::std::string::String>,
}
impl CreateReservationInput {
    /// <p>The number of Redshift Processing Units (RPUs) to reserve.</p>
    pub fn capacity(&self) -> ::std::option::Option<i32> {
        self.capacity
    }
    /// <p>The ID of the offering associated with the reservation. The offering determines the payment schedule for the reservation.</p>
    pub fn offering_id(&self) -> ::std::option::Option<&str> {
        self.offering_id.as_deref()
    }
    /// <p>A unique, case-sensitive identifier that you provide to ensure the idempotency of the request. If not provided, the Amazon Web Services SDK populates this field. This token must be a valid UUIDv4 value. For more information about idempotency, see <a href="https://aws.amazon.com/builders-library/making-retries-safe-with-idempotent-APIs/"> Making retries safe with idempotent APIs </a>.</p>
    pub fn client_token(&self) -> ::std::option::Option<&str> {
        self.client_token.as_deref()
    }
}
impl CreateReservationInput {
    /// Creates a new builder-style object to manufacture [`CreateReservationInput`](crate::operation::create_reservation::CreateReservationInput).
    pub fn builder() -> crate::operation::create_reservation::builders::CreateReservationInputBuilder {
        crate::operation::create_reservation::builders::CreateReservationInputBuilder::default()
    }
}

/// A builder for [`CreateReservationInput`](crate::operation::create_reservation::CreateReservationInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateReservationInputBuilder {
    pub(crate) capacity: ::std::option::Option<i32>,
    pub(crate) offering_id: ::std::option::Option<::std::string::String>,
    pub(crate) client_token: ::std::option::Option<::std::string::String>,
}
impl CreateReservationInputBuilder {
    /// <p>The number of Redshift Processing Units (RPUs) to reserve.</p>
    /// This field is required.
    pub fn capacity(mut self, input: i32) -> Self {
        self.capacity = ::std::option::Option::Some(input);
        self
    }
    /// <p>The number of Redshift Processing Units (RPUs) to reserve.</p>
    pub fn set_capacity(mut self, input: ::std::option::Option<i32>) -> Self {
        self.capacity = input;
        self
    }
    /// <p>The number of Redshift Processing Units (RPUs) to reserve.</p>
    pub fn get_capacity(&self) -> &::std::option::Option<i32> {
        &self.capacity
    }
    /// <p>The ID of the offering associated with the reservation. The offering determines the payment schedule for the reservation.</p>
    /// This field is required.
    pub fn offering_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.offering_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the offering associated with the reservation. The offering determines the payment schedule for the reservation.</p>
    pub fn set_offering_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.offering_id = input;
        self
    }
    /// <p>The ID of the offering associated with the reservation. The offering determines the payment schedule for the reservation.</p>
    pub fn get_offering_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.offering_id
    }
    /// <p>A unique, case-sensitive identifier that you provide to ensure the idempotency of the request. If not provided, the Amazon Web Services SDK populates this field. This token must be a valid UUIDv4 value. For more information about idempotency, see <a href="https://aws.amazon.com/builders-library/making-retries-safe-with-idempotent-APIs/"> Making retries safe with idempotent APIs </a>.</p>
    pub fn client_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.client_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A unique, case-sensitive identifier that you provide to ensure the idempotency of the request. If not provided, the Amazon Web Services SDK populates this field. This token must be a valid UUIDv4 value. For more information about idempotency, see <a href="https://aws.amazon.com/builders-library/making-retries-safe-with-idempotent-APIs/"> Making retries safe with idempotent APIs </a>.</p>
    pub fn set_client_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.client_token = input;
        self
    }
    /// <p>A unique, case-sensitive identifier that you provide to ensure the idempotency of the request. If not provided, the Amazon Web Services SDK populates this field. This token must be a valid UUIDv4 value. For more information about idempotency, see <a href="https://aws.amazon.com/builders-library/making-retries-safe-with-idempotent-APIs/"> Making retries safe with idempotent APIs </a>.</p>
    pub fn get_client_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.client_token
    }
    /// Consumes the builder and constructs a [`CreateReservationInput`](crate::operation::create_reservation::CreateReservationInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::create_reservation::CreateReservationInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::create_reservation::CreateReservationInput {
            capacity: self.capacity,
            offering_id: self.offering_id,
            client_token: self.client_token,
        })
    }
}
