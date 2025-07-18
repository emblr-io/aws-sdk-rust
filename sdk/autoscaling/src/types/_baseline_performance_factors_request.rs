// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The baseline performance to consider, using an instance family as a baseline reference. The instance family establishes the lowest acceptable level of performance. Auto Scaling uses this baseline to guide instance type selection, but there is no guarantee that the selected instance types will always exceed the baseline for every application.</p>
/// <p>Currently, this parameter only supports CPU performance as a baseline performance factor. For example, specifying <code>c6i</code> uses the CPU performance of the <code>c6i</code> family as the baseline reference.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct BaselinePerformanceFactorsRequest {
    /// <p>The CPU performance to consider, using an instance family as the baseline reference.</p>
    pub cpu: ::std::option::Option<crate::types::CpuPerformanceFactorRequest>,
}
impl BaselinePerformanceFactorsRequest {
    /// <p>The CPU performance to consider, using an instance family as the baseline reference.</p>
    pub fn cpu(&self) -> ::std::option::Option<&crate::types::CpuPerformanceFactorRequest> {
        self.cpu.as_ref()
    }
}
impl BaselinePerformanceFactorsRequest {
    /// Creates a new builder-style object to manufacture [`BaselinePerformanceFactorsRequest`](crate::types::BaselinePerformanceFactorsRequest).
    pub fn builder() -> crate::types::builders::BaselinePerformanceFactorsRequestBuilder {
        crate::types::builders::BaselinePerformanceFactorsRequestBuilder::default()
    }
}

/// A builder for [`BaselinePerformanceFactorsRequest`](crate::types::BaselinePerformanceFactorsRequest).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct BaselinePerformanceFactorsRequestBuilder {
    pub(crate) cpu: ::std::option::Option<crate::types::CpuPerformanceFactorRequest>,
}
impl BaselinePerformanceFactorsRequestBuilder {
    /// <p>The CPU performance to consider, using an instance family as the baseline reference.</p>
    pub fn cpu(mut self, input: crate::types::CpuPerformanceFactorRequest) -> Self {
        self.cpu = ::std::option::Option::Some(input);
        self
    }
    /// <p>The CPU performance to consider, using an instance family as the baseline reference.</p>
    pub fn set_cpu(mut self, input: ::std::option::Option<crate::types::CpuPerformanceFactorRequest>) -> Self {
        self.cpu = input;
        self
    }
    /// <p>The CPU performance to consider, using an instance family as the baseline reference.</p>
    pub fn get_cpu(&self) -> &::std::option::Option<crate::types::CpuPerformanceFactorRequest> {
        &self.cpu
    }
    /// Consumes the builder and constructs a [`BaselinePerformanceFactorsRequest`](crate::types::BaselinePerformanceFactorsRequest).
    pub fn build(self) -> crate::types::BaselinePerformanceFactorsRequest {
        crate::types::BaselinePerformanceFactorsRequest { cpu: self.cpu }
    }
}
