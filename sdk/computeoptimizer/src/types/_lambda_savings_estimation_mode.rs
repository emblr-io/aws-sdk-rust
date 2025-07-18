// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Describes the savings estimation used for calculating savings opportunity for Lambda functions.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct LambdaSavingsEstimationMode {
    /// <p>Describes the source for calculation of savings opportunity for Lambda functions.</p>
    pub source: ::std::option::Option<crate::types::LambdaSavingsEstimationModeSource>,
}
impl LambdaSavingsEstimationMode {
    /// <p>Describes the source for calculation of savings opportunity for Lambda functions.</p>
    pub fn source(&self) -> ::std::option::Option<&crate::types::LambdaSavingsEstimationModeSource> {
        self.source.as_ref()
    }
}
impl LambdaSavingsEstimationMode {
    /// Creates a new builder-style object to manufacture [`LambdaSavingsEstimationMode`](crate::types::LambdaSavingsEstimationMode).
    pub fn builder() -> crate::types::builders::LambdaSavingsEstimationModeBuilder {
        crate::types::builders::LambdaSavingsEstimationModeBuilder::default()
    }
}

/// A builder for [`LambdaSavingsEstimationMode`](crate::types::LambdaSavingsEstimationMode).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct LambdaSavingsEstimationModeBuilder {
    pub(crate) source: ::std::option::Option<crate::types::LambdaSavingsEstimationModeSource>,
}
impl LambdaSavingsEstimationModeBuilder {
    /// <p>Describes the source for calculation of savings opportunity for Lambda functions.</p>
    pub fn source(mut self, input: crate::types::LambdaSavingsEstimationModeSource) -> Self {
        self.source = ::std::option::Option::Some(input);
        self
    }
    /// <p>Describes the source for calculation of savings opportunity for Lambda functions.</p>
    pub fn set_source(mut self, input: ::std::option::Option<crate::types::LambdaSavingsEstimationModeSource>) -> Self {
        self.source = input;
        self
    }
    /// <p>Describes the source for calculation of savings opportunity for Lambda functions.</p>
    pub fn get_source(&self) -> &::std::option::Option<crate::types::LambdaSavingsEstimationModeSource> {
        &self.source
    }
    /// Consumes the builder and constructs a [`LambdaSavingsEstimationMode`](crate::types::LambdaSavingsEstimationMode).
    pub fn build(self) -> crate::types::LambdaSavingsEstimationMode {
        crate::types::LambdaSavingsEstimationMode { source: self.source }
    }
}
