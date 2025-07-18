// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The wrapper for position solver details.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct PositionSolverDetails {
    /// <p>The Semtech GNSS solver object details.</p>
    pub semtech_gnss: ::std::option::Option<crate::types::SemtechGnssDetail>,
}
impl PositionSolverDetails {
    /// <p>The Semtech GNSS solver object details.</p>
    pub fn semtech_gnss(&self) -> ::std::option::Option<&crate::types::SemtechGnssDetail> {
        self.semtech_gnss.as_ref()
    }
}
impl PositionSolverDetails {
    /// Creates a new builder-style object to manufacture [`PositionSolverDetails`](crate::types::PositionSolverDetails).
    pub fn builder() -> crate::types::builders::PositionSolverDetailsBuilder {
        crate::types::builders::PositionSolverDetailsBuilder::default()
    }
}

/// A builder for [`PositionSolverDetails`](crate::types::PositionSolverDetails).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct PositionSolverDetailsBuilder {
    pub(crate) semtech_gnss: ::std::option::Option<crate::types::SemtechGnssDetail>,
}
impl PositionSolverDetailsBuilder {
    /// <p>The Semtech GNSS solver object details.</p>
    pub fn semtech_gnss(mut self, input: crate::types::SemtechGnssDetail) -> Self {
        self.semtech_gnss = ::std::option::Option::Some(input);
        self
    }
    /// <p>The Semtech GNSS solver object details.</p>
    pub fn set_semtech_gnss(mut self, input: ::std::option::Option<crate::types::SemtechGnssDetail>) -> Self {
        self.semtech_gnss = input;
        self
    }
    /// <p>The Semtech GNSS solver object details.</p>
    pub fn get_semtech_gnss(&self) -> &::std::option::Option<crate::types::SemtechGnssDetail> {
        &self.semtech_gnss
    }
    /// Consumes the builder and constructs a [`PositionSolverDetails`](crate::types::PositionSolverDetails).
    pub fn build(self) -> crate::types::PositionSolverDetails {
        crate::types::PositionSolverDetails {
            semtech_gnss: self.semtech_gnss,
        }
    }
}
