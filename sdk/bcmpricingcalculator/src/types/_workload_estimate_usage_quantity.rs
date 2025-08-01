// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Represents a usage quantity for a workload estimate.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct WorkloadEstimateUsageQuantity {
    /// <p>The unit of measurement for the usage quantity.</p>
    pub unit: ::std::option::Option<::std::string::String>,
    /// <p>The numeric value of the usage quantity.</p>
    pub amount: ::std::option::Option<f64>,
}
impl WorkloadEstimateUsageQuantity {
    /// <p>The unit of measurement for the usage quantity.</p>
    pub fn unit(&self) -> ::std::option::Option<&str> {
        self.unit.as_deref()
    }
    /// <p>The numeric value of the usage quantity.</p>
    pub fn amount(&self) -> ::std::option::Option<f64> {
        self.amount
    }
}
impl WorkloadEstimateUsageQuantity {
    /// Creates a new builder-style object to manufacture [`WorkloadEstimateUsageQuantity`](crate::types::WorkloadEstimateUsageQuantity).
    pub fn builder() -> crate::types::builders::WorkloadEstimateUsageQuantityBuilder {
        crate::types::builders::WorkloadEstimateUsageQuantityBuilder::default()
    }
}

/// A builder for [`WorkloadEstimateUsageQuantity`](crate::types::WorkloadEstimateUsageQuantity).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct WorkloadEstimateUsageQuantityBuilder {
    pub(crate) unit: ::std::option::Option<::std::string::String>,
    pub(crate) amount: ::std::option::Option<f64>,
}
impl WorkloadEstimateUsageQuantityBuilder {
    /// <p>The unit of measurement for the usage quantity.</p>
    pub fn unit(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.unit = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unit of measurement for the usage quantity.</p>
    pub fn set_unit(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.unit = input;
        self
    }
    /// <p>The unit of measurement for the usage quantity.</p>
    pub fn get_unit(&self) -> &::std::option::Option<::std::string::String> {
        &self.unit
    }
    /// <p>The numeric value of the usage quantity.</p>
    pub fn amount(mut self, input: f64) -> Self {
        self.amount = ::std::option::Option::Some(input);
        self
    }
    /// <p>The numeric value of the usage quantity.</p>
    pub fn set_amount(mut self, input: ::std::option::Option<f64>) -> Self {
        self.amount = input;
        self
    }
    /// <p>The numeric value of the usage quantity.</p>
    pub fn get_amount(&self) -> &::std::option::Option<f64> {
        &self.amount
    }
    /// Consumes the builder and constructs a [`WorkloadEstimateUsageQuantity`](crate::types::WorkloadEstimateUsageQuantity).
    pub fn build(self) -> crate::types::WorkloadEstimateUsageQuantity {
        crate::types::WorkloadEstimateUsageQuantity {
            unit: self.unit,
            amount: self.amount,
        }
    }
}
