// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Specifies a Diffie-Hellman group number for the VPN tunnel for phase 2 IKE negotiations.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct Phase2DhGroupNumbersRequestListValue {
    /// <p>The Diffie-Hellmann group number.</p>
    pub value: ::std::option::Option<i32>,
}
impl Phase2DhGroupNumbersRequestListValue {
    /// <p>The Diffie-Hellmann group number.</p>
    pub fn value(&self) -> ::std::option::Option<i32> {
        self.value
    }
}
impl Phase2DhGroupNumbersRequestListValue {
    /// Creates a new builder-style object to manufacture [`Phase2DhGroupNumbersRequestListValue`](crate::types::Phase2DhGroupNumbersRequestListValue).
    pub fn builder() -> crate::types::builders::Phase2DhGroupNumbersRequestListValueBuilder {
        crate::types::builders::Phase2DhGroupNumbersRequestListValueBuilder::default()
    }
}

/// A builder for [`Phase2DhGroupNumbersRequestListValue`](crate::types::Phase2DhGroupNumbersRequestListValue).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct Phase2DhGroupNumbersRequestListValueBuilder {
    pub(crate) value: ::std::option::Option<i32>,
}
impl Phase2DhGroupNumbersRequestListValueBuilder {
    /// <p>The Diffie-Hellmann group number.</p>
    pub fn value(mut self, input: i32) -> Self {
        self.value = ::std::option::Option::Some(input);
        self
    }
    /// <p>The Diffie-Hellmann group number.</p>
    pub fn set_value(mut self, input: ::std::option::Option<i32>) -> Self {
        self.value = input;
        self
    }
    /// <p>The Diffie-Hellmann group number.</p>
    pub fn get_value(&self) -> &::std::option::Option<i32> {
        &self.value
    }
    /// Consumes the builder and constructs a [`Phase2DhGroupNumbersRequestListValue`](crate::types::Phase2DhGroupNumbersRequestListValue).
    pub fn build(self) -> crate::types::Phase2DhGroupNumbersRequestListValue {
        crate::types::Phase2DhGroupNumbersRequestListValue { value: self.value }
    }
}
