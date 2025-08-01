// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The aggregate vCPU, memory, and storage resources used from the time job start executing till the time job is terminated, rounded up to the nearest second.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct TotalResourceUtilization {
    /// <p>The aggregated vCPU used per hour from the time job start executing till the time job is terminated.</p>
    pub v_cpu_hour: ::std::option::Option<f64>,
    /// <p>The aggregated memory used per hour from the time job start executing till the time job is terminated.</p>
    pub memory_gb_hour: ::std::option::Option<f64>,
    /// <p>The aggregated storage used per hour from the time job start executing till the time job is terminated.</p>
    pub storage_gb_hour: ::std::option::Option<f64>,
}
impl TotalResourceUtilization {
    /// <p>The aggregated vCPU used per hour from the time job start executing till the time job is terminated.</p>
    pub fn v_cpu_hour(&self) -> ::std::option::Option<f64> {
        self.v_cpu_hour
    }
    /// <p>The aggregated memory used per hour from the time job start executing till the time job is terminated.</p>
    pub fn memory_gb_hour(&self) -> ::std::option::Option<f64> {
        self.memory_gb_hour
    }
    /// <p>The aggregated storage used per hour from the time job start executing till the time job is terminated.</p>
    pub fn storage_gb_hour(&self) -> ::std::option::Option<f64> {
        self.storage_gb_hour
    }
}
impl TotalResourceUtilization {
    /// Creates a new builder-style object to manufacture [`TotalResourceUtilization`](crate::types::TotalResourceUtilization).
    pub fn builder() -> crate::types::builders::TotalResourceUtilizationBuilder {
        crate::types::builders::TotalResourceUtilizationBuilder::default()
    }
}

/// A builder for [`TotalResourceUtilization`](crate::types::TotalResourceUtilization).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct TotalResourceUtilizationBuilder {
    pub(crate) v_cpu_hour: ::std::option::Option<f64>,
    pub(crate) memory_gb_hour: ::std::option::Option<f64>,
    pub(crate) storage_gb_hour: ::std::option::Option<f64>,
}
impl TotalResourceUtilizationBuilder {
    /// <p>The aggregated vCPU used per hour from the time job start executing till the time job is terminated.</p>
    pub fn v_cpu_hour(mut self, input: f64) -> Self {
        self.v_cpu_hour = ::std::option::Option::Some(input);
        self
    }
    /// <p>The aggregated vCPU used per hour from the time job start executing till the time job is terminated.</p>
    pub fn set_v_cpu_hour(mut self, input: ::std::option::Option<f64>) -> Self {
        self.v_cpu_hour = input;
        self
    }
    /// <p>The aggregated vCPU used per hour from the time job start executing till the time job is terminated.</p>
    pub fn get_v_cpu_hour(&self) -> &::std::option::Option<f64> {
        &self.v_cpu_hour
    }
    /// <p>The aggregated memory used per hour from the time job start executing till the time job is terminated.</p>
    pub fn memory_gb_hour(mut self, input: f64) -> Self {
        self.memory_gb_hour = ::std::option::Option::Some(input);
        self
    }
    /// <p>The aggregated memory used per hour from the time job start executing till the time job is terminated.</p>
    pub fn set_memory_gb_hour(mut self, input: ::std::option::Option<f64>) -> Self {
        self.memory_gb_hour = input;
        self
    }
    /// <p>The aggregated memory used per hour from the time job start executing till the time job is terminated.</p>
    pub fn get_memory_gb_hour(&self) -> &::std::option::Option<f64> {
        &self.memory_gb_hour
    }
    /// <p>The aggregated storage used per hour from the time job start executing till the time job is terminated.</p>
    pub fn storage_gb_hour(mut self, input: f64) -> Self {
        self.storage_gb_hour = ::std::option::Option::Some(input);
        self
    }
    /// <p>The aggregated storage used per hour from the time job start executing till the time job is terminated.</p>
    pub fn set_storage_gb_hour(mut self, input: ::std::option::Option<f64>) -> Self {
        self.storage_gb_hour = input;
        self
    }
    /// <p>The aggregated storage used per hour from the time job start executing till the time job is terminated.</p>
    pub fn get_storage_gb_hour(&self) -> &::std::option::Option<f64> {
        &self.storage_gb_hour
    }
    /// Consumes the builder and constructs a [`TotalResourceUtilization`](crate::types::TotalResourceUtilization).
    pub fn build(self) -> crate::types::TotalResourceUtilization {
        crate::types::TotalResourceUtilization {
            v_cpu_hour: self.v_cpu_hour,
            memory_gb_hour: self.memory_gb_hour,
            storage_gb_hour: self.storage_gb_hour,
        }
    }
}
