// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The overall resiliency score, returned as an object that includes the disruption score and outage score.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ResiliencyScore {
    /// <p>The outage score for a valid key.</p>
    pub score: f64,
    /// <p>The disruption score for a valid key.</p>
    pub disruption_score: ::std::collections::HashMap<crate::types::DisruptionType, f64>,
    /// <p>The score generated by Resilience Hub for the scoring component after running an assessment.</p>
    /// <p>For example, if the <code>score</code> is 25 points, it indicates the overall score of your application generated by Resilience Hub after running an assessment.</p>
    pub component_score:
        ::std::option::Option<::std::collections::HashMap<crate::types::ResiliencyScoreType, crate::types::ScoringComponentResiliencyScore>>,
}
impl ResiliencyScore {
    /// <p>The outage score for a valid key.</p>
    pub fn score(&self) -> f64 {
        self.score
    }
    /// <p>The disruption score for a valid key.</p>
    pub fn disruption_score(&self) -> &::std::collections::HashMap<crate::types::DisruptionType, f64> {
        &self.disruption_score
    }
    /// <p>The score generated by Resilience Hub for the scoring component after running an assessment.</p>
    /// <p>For example, if the <code>score</code> is 25 points, it indicates the overall score of your application generated by Resilience Hub after running an assessment.</p>
    pub fn component_score(
        &self,
    ) -> ::std::option::Option<&::std::collections::HashMap<crate::types::ResiliencyScoreType, crate::types::ScoringComponentResiliencyScore>> {
        self.component_score.as_ref()
    }
}
impl ResiliencyScore {
    /// Creates a new builder-style object to manufacture [`ResiliencyScore`](crate::types::ResiliencyScore).
    pub fn builder() -> crate::types::builders::ResiliencyScoreBuilder {
        crate::types::builders::ResiliencyScoreBuilder::default()
    }
}

/// A builder for [`ResiliencyScore`](crate::types::ResiliencyScore).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ResiliencyScoreBuilder {
    pub(crate) score: ::std::option::Option<f64>,
    pub(crate) disruption_score: ::std::option::Option<::std::collections::HashMap<crate::types::DisruptionType, f64>>,
    pub(crate) component_score:
        ::std::option::Option<::std::collections::HashMap<crate::types::ResiliencyScoreType, crate::types::ScoringComponentResiliencyScore>>,
}
impl ResiliencyScoreBuilder {
    /// <p>The outage score for a valid key.</p>
    /// This field is required.
    pub fn score(mut self, input: f64) -> Self {
        self.score = ::std::option::Option::Some(input);
        self
    }
    /// <p>The outage score for a valid key.</p>
    pub fn set_score(mut self, input: ::std::option::Option<f64>) -> Self {
        self.score = input;
        self
    }
    /// <p>The outage score for a valid key.</p>
    pub fn get_score(&self) -> &::std::option::Option<f64> {
        &self.score
    }
    /// Adds a key-value pair to `disruption_score`.
    ///
    /// To override the contents of this collection use [`set_disruption_score`](Self::set_disruption_score).
    ///
    /// <p>The disruption score for a valid key.</p>
    pub fn disruption_score(mut self, k: crate::types::DisruptionType, v: f64) -> Self {
        let mut hash_map = self.disruption_score.unwrap_or_default();
        hash_map.insert(k, v);
        self.disruption_score = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>The disruption score for a valid key.</p>
    pub fn set_disruption_score(mut self, input: ::std::option::Option<::std::collections::HashMap<crate::types::DisruptionType, f64>>) -> Self {
        self.disruption_score = input;
        self
    }
    /// <p>The disruption score for a valid key.</p>
    pub fn get_disruption_score(&self) -> &::std::option::Option<::std::collections::HashMap<crate::types::DisruptionType, f64>> {
        &self.disruption_score
    }
    /// Adds a key-value pair to `component_score`.
    ///
    /// To override the contents of this collection use [`set_component_score`](Self::set_component_score).
    ///
    /// <p>The score generated by Resilience Hub for the scoring component after running an assessment.</p>
    /// <p>For example, if the <code>score</code> is 25 points, it indicates the overall score of your application generated by Resilience Hub after running an assessment.</p>
    pub fn component_score(mut self, k: crate::types::ResiliencyScoreType, v: crate::types::ScoringComponentResiliencyScore) -> Self {
        let mut hash_map = self.component_score.unwrap_or_default();
        hash_map.insert(k, v);
        self.component_score = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>The score generated by Resilience Hub for the scoring component after running an assessment.</p>
    /// <p>For example, if the <code>score</code> is 25 points, it indicates the overall score of your application generated by Resilience Hub after running an assessment.</p>
    pub fn set_component_score(
        mut self,
        input: ::std::option::Option<::std::collections::HashMap<crate::types::ResiliencyScoreType, crate::types::ScoringComponentResiliencyScore>>,
    ) -> Self {
        self.component_score = input;
        self
    }
    /// <p>The score generated by Resilience Hub for the scoring component after running an assessment.</p>
    /// <p>For example, if the <code>score</code> is 25 points, it indicates the overall score of your application generated by Resilience Hub after running an assessment.</p>
    pub fn get_component_score(
        &self,
    ) -> &::std::option::Option<::std::collections::HashMap<crate::types::ResiliencyScoreType, crate::types::ScoringComponentResiliencyScore>> {
        &self.component_score
    }
    /// Consumes the builder and constructs a [`ResiliencyScore`](crate::types::ResiliencyScore).
    /// This method will fail if any of the following fields are not set:
    /// - [`disruption_score`](crate::types::builders::ResiliencyScoreBuilder::disruption_score)
    pub fn build(self) -> ::std::result::Result<crate::types::ResiliencyScore, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::ResiliencyScore {
            score: self.score.unwrap_or_default(),
            disruption_score: self.disruption_score.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "disruption_score",
                    "disruption_score was not specified but it is required when building ResiliencyScore",
                )
            })?,
            component_score: self.component_score,
        })
    }
}
