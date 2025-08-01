// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeReservationInput {
    /// <p>The Amazon Resource Name (ARN) of the offering.</p>
    pub reservation_arn: ::std::option::Option<::std::string::String>,
}
impl DescribeReservationInput {
    /// <p>The Amazon Resource Name (ARN) of the offering.</p>
    pub fn reservation_arn(&self) -> ::std::option::Option<&str> {
        self.reservation_arn.as_deref()
    }
}
impl DescribeReservationInput {
    /// Creates a new builder-style object to manufacture [`DescribeReservationInput`](crate::operation::describe_reservation::DescribeReservationInput).
    pub fn builder() -> crate::operation::describe_reservation::builders::DescribeReservationInputBuilder {
        crate::operation::describe_reservation::builders::DescribeReservationInputBuilder::default()
    }
}

/// A builder for [`DescribeReservationInput`](crate::operation::describe_reservation::DescribeReservationInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeReservationInputBuilder {
    pub(crate) reservation_arn: ::std::option::Option<::std::string::String>,
}
impl DescribeReservationInputBuilder {
    /// <p>The Amazon Resource Name (ARN) of the offering.</p>
    /// This field is required.
    pub fn reservation_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.reservation_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the offering.</p>
    pub fn set_reservation_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.reservation_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the offering.</p>
    pub fn get_reservation_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.reservation_arn
    }
    /// Consumes the builder and constructs a [`DescribeReservationInput`](crate::operation::describe_reservation::DescribeReservationInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::describe_reservation::DescribeReservationInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::describe_reservation::DescribeReservationInput {
            reservation_arn: self.reservation_arn,
        })
    }
}
