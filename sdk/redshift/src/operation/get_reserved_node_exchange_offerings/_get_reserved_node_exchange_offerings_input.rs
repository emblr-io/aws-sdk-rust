// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p></p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetReservedNodeExchangeOfferingsInput {
    /// <p>A string representing the node identifier for the DC1 Reserved Node to be exchanged.</p>
    pub reserved_node_id: ::std::option::Option<::std::string::String>,
    /// <p>An integer setting the maximum number of ReservedNodeOfferings to retrieve.</p>
    pub max_records: ::std::option::Option<i32>,
    /// <p>A value that indicates the starting point for the next set of ReservedNodeOfferings.</p>
    pub marker: ::std::option::Option<::std::string::String>,
}
impl GetReservedNodeExchangeOfferingsInput {
    /// <p>A string representing the node identifier for the DC1 Reserved Node to be exchanged.</p>
    pub fn reserved_node_id(&self) -> ::std::option::Option<&str> {
        self.reserved_node_id.as_deref()
    }
    /// <p>An integer setting the maximum number of ReservedNodeOfferings to retrieve.</p>
    pub fn max_records(&self) -> ::std::option::Option<i32> {
        self.max_records
    }
    /// <p>A value that indicates the starting point for the next set of ReservedNodeOfferings.</p>
    pub fn marker(&self) -> ::std::option::Option<&str> {
        self.marker.as_deref()
    }
}
impl GetReservedNodeExchangeOfferingsInput {
    /// Creates a new builder-style object to manufacture [`GetReservedNodeExchangeOfferingsInput`](crate::operation::get_reserved_node_exchange_offerings::GetReservedNodeExchangeOfferingsInput).
    pub fn builder() -> crate::operation::get_reserved_node_exchange_offerings::builders::GetReservedNodeExchangeOfferingsInputBuilder {
        crate::operation::get_reserved_node_exchange_offerings::builders::GetReservedNodeExchangeOfferingsInputBuilder::default()
    }
}

/// A builder for [`GetReservedNodeExchangeOfferingsInput`](crate::operation::get_reserved_node_exchange_offerings::GetReservedNodeExchangeOfferingsInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetReservedNodeExchangeOfferingsInputBuilder {
    pub(crate) reserved_node_id: ::std::option::Option<::std::string::String>,
    pub(crate) max_records: ::std::option::Option<i32>,
    pub(crate) marker: ::std::option::Option<::std::string::String>,
}
impl GetReservedNodeExchangeOfferingsInputBuilder {
    /// <p>A string representing the node identifier for the DC1 Reserved Node to be exchanged.</p>
    /// This field is required.
    pub fn reserved_node_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.reserved_node_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A string representing the node identifier for the DC1 Reserved Node to be exchanged.</p>
    pub fn set_reserved_node_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.reserved_node_id = input;
        self
    }
    /// <p>A string representing the node identifier for the DC1 Reserved Node to be exchanged.</p>
    pub fn get_reserved_node_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.reserved_node_id
    }
    /// <p>An integer setting the maximum number of ReservedNodeOfferings to retrieve.</p>
    pub fn max_records(mut self, input: i32) -> Self {
        self.max_records = ::std::option::Option::Some(input);
        self
    }
    /// <p>An integer setting the maximum number of ReservedNodeOfferings to retrieve.</p>
    pub fn set_max_records(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_records = input;
        self
    }
    /// <p>An integer setting the maximum number of ReservedNodeOfferings to retrieve.</p>
    pub fn get_max_records(&self) -> &::std::option::Option<i32> {
        &self.max_records
    }
    /// <p>A value that indicates the starting point for the next set of ReservedNodeOfferings.</p>
    pub fn marker(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.marker = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A value that indicates the starting point for the next set of ReservedNodeOfferings.</p>
    pub fn set_marker(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.marker = input;
        self
    }
    /// <p>A value that indicates the starting point for the next set of ReservedNodeOfferings.</p>
    pub fn get_marker(&self) -> &::std::option::Option<::std::string::String> {
        &self.marker
    }
    /// Consumes the builder and constructs a [`GetReservedNodeExchangeOfferingsInput`](crate::operation::get_reserved_node_exchange_offerings::GetReservedNodeExchangeOfferingsInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::get_reserved_node_exchange_offerings::GetReservedNodeExchangeOfferingsInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(
            crate::operation::get_reserved_node_exchange_offerings::GetReservedNodeExchangeOfferingsInput {
                reserved_node_id: self.reserved_node_id,
                max_records: self.max_records,
                marker: self.marker,
            },
        )
    }
}
