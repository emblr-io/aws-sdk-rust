// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Describes the type of service for a VPC endpoint.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ServiceTypeDetail {
    /// <p>The type of service.</p>
    pub service_type: ::std::option::Option<crate::types::ServiceType>,
}
impl ServiceTypeDetail {
    /// <p>The type of service.</p>
    pub fn service_type(&self) -> ::std::option::Option<&crate::types::ServiceType> {
        self.service_type.as_ref()
    }
}
impl ServiceTypeDetail {
    /// Creates a new builder-style object to manufacture [`ServiceTypeDetail`](crate::types::ServiceTypeDetail).
    pub fn builder() -> crate::types::builders::ServiceTypeDetailBuilder {
        crate::types::builders::ServiceTypeDetailBuilder::default()
    }
}

/// A builder for [`ServiceTypeDetail`](crate::types::ServiceTypeDetail).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ServiceTypeDetailBuilder {
    pub(crate) service_type: ::std::option::Option<crate::types::ServiceType>,
}
impl ServiceTypeDetailBuilder {
    /// <p>The type of service.</p>
    pub fn service_type(mut self, input: crate::types::ServiceType) -> Self {
        self.service_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The type of service.</p>
    pub fn set_service_type(mut self, input: ::std::option::Option<crate::types::ServiceType>) -> Self {
        self.service_type = input;
        self
    }
    /// <p>The type of service.</p>
    pub fn get_service_type(&self) -> &::std::option::Option<crate::types::ServiceType> {
        &self.service_type
    }
    /// Consumes the builder and constructs a [`ServiceTypeDetail`](crate::types::ServiceTypeDetail).
    pub fn build(self) -> crate::types::ServiceTypeDetail {
        crate::types::ServiceTypeDetail {
            service_type: self.service_type,
        }
    }
}
