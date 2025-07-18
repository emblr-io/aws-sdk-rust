// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A flag to indicating that automatic model tuning (AMT) has detected model convergence, defined as a lack of significant improvement (1% or less) against an objective metric.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ConvergenceDetected {
    /// <p>A flag to stop a tuning job once AMT has detected that the job has converged.</p>
    pub complete_on_convergence: ::std::option::Option<crate::types::CompleteOnConvergence>,
}
impl ConvergenceDetected {
    /// <p>A flag to stop a tuning job once AMT has detected that the job has converged.</p>
    pub fn complete_on_convergence(&self) -> ::std::option::Option<&crate::types::CompleteOnConvergence> {
        self.complete_on_convergence.as_ref()
    }
}
impl ConvergenceDetected {
    /// Creates a new builder-style object to manufacture [`ConvergenceDetected`](crate::types::ConvergenceDetected).
    pub fn builder() -> crate::types::builders::ConvergenceDetectedBuilder {
        crate::types::builders::ConvergenceDetectedBuilder::default()
    }
}

/// A builder for [`ConvergenceDetected`](crate::types::ConvergenceDetected).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ConvergenceDetectedBuilder {
    pub(crate) complete_on_convergence: ::std::option::Option<crate::types::CompleteOnConvergence>,
}
impl ConvergenceDetectedBuilder {
    /// <p>A flag to stop a tuning job once AMT has detected that the job has converged.</p>
    pub fn complete_on_convergence(mut self, input: crate::types::CompleteOnConvergence) -> Self {
        self.complete_on_convergence = ::std::option::Option::Some(input);
        self
    }
    /// <p>A flag to stop a tuning job once AMT has detected that the job has converged.</p>
    pub fn set_complete_on_convergence(mut self, input: ::std::option::Option<crate::types::CompleteOnConvergence>) -> Self {
        self.complete_on_convergence = input;
        self
    }
    /// <p>A flag to stop a tuning job once AMT has detected that the job has converged.</p>
    pub fn get_complete_on_convergence(&self) -> &::std::option::Option<crate::types::CompleteOnConvergence> {
        &self.complete_on_convergence
    }
    /// Consumes the builder and constructs a [`ConvergenceDetected`](crate::types::ConvergenceDetected).
    pub fn build(self) -> crate::types::ConvergenceDetected {
        crate::types::ConvergenceDetected {
            complete_on_convergence: self.complete_on_convergence,
        }
    }
}
