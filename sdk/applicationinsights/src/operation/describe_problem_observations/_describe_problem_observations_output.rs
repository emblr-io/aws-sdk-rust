// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeProblemObservationsOutput {
    /// <p>Observations related to the problem.</p>
    pub related_observations: ::std::option::Option<crate::types::RelatedObservations>,
    _request_id: Option<String>,
}
impl DescribeProblemObservationsOutput {
    /// <p>Observations related to the problem.</p>
    pub fn related_observations(&self) -> ::std::option::Option<&crate::types::RelatedObservations> {
        self.related_observations.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for DescribeProblemObservationsOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DescribeProblemObservationsOutput {
    /// Creates a new builder-style object to manufacture [`DescribeProblemObservationsOutput`](crate::operation::describe_problem_observations::DescribeProblemObservationsOutput).
    pub fn builder() -> crate::operation::describe_problem_observations::builders::DescribeProblemObservationsOutputBuilder {
        crate::operation::describe_problem_observations::builders::DescribeProblemObservationsOutputBuilder::default()
    }
}

/// A builder for [`DescribeProblemObservationsOutput`](crate::operation::describe_problem_observations::DescribeProblemObservationsOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeProblemObservationsOutputBuilder {
    pub(crate) related_observations: ::std::option::Option<crate::types::RelatedObservations>,
    _request_id: Option<String>,
}
impl DescribeProblemObservationsOutputBuilder {
    /// <p>Observations related to the problem.</p>
    pub fn related_observations(mut self, input: crate::types::RelatedObservations) -> Self {
        self.related_observations = ::std::option::Option::Some(input);
        self
    }
    /// <p>Observations related to the problem.</p>
    pub fn set_related_observations(mut self, input: ::std::option::Option<crate::types::RelatedObservations>) -> Self {
        self.related_observations = input;
        self
    }
    /// <p>Observations related to the problem.</p>
    pub fn get_related_observations(&self) -> &::std::option::Option<crate::types::RelatedObservations> {
        &self.related_observations
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`DescribeProblemObservationsOutput`](crate::operation::describe_problem_observations::DescribeProblemObservationsOutput).
    pub fn build(self) -> crate::operation::describe_problem_observations::DescribeProblemObservationsOutput {
        crate::operation::describe_problem_observations::DescribeProblemObservationsOutput {
            related_observations: self.related_observations,
            _request_id: self._request_id,
        }
    }
}
