// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Detailed information about the accuracy of an entity recognizer.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct EntityRecognizerEvaluationMetrics {
    /// <p>A measure of the usefulness of the recognizer results in the test data. High precision means that the recognizer returned substantially more relevant results than irrelevant ones.</p>
    pub precision: ::std::option::Option<f64>,
    /// <p>A measure of how complete the recognizer results are for the test data. High recall means that the recognizer returned most of the relevant results.</p>
    pub recall: ::std::option::Option<f64>,
    /// <p>A measure of how accurate the recognizer results are for the test data. It is derived from the <code>Precision</code> and <code>Recall</code> values. The <code>F1Score</code> is the harmonic average of the two scores. For plain text entity recognizer models, the range is 0 to 100, where 100 is the best score. For PDF/Word entity recognizer models, the range is 0 to 1, where 1 is the best score.</p>
    pub f1_score: ::std::option::Option<f64>,
}
impl EntityRecognizerEvaluationMetrics {
    /// <p>A measure of the usefulness of the recognizer results in the test data. High precision means that the recognizer returned substantially more relevant results than irrelevant ones.</p>
    pub fn precision(&self) -> ::std::option::Option<f64> {
        self.precision
    }
    /// <p>A measure of how complete the recognizer results are for the test data. High recall means that the recognizer returned most of the relevant results.</p>
    pub fn recall(&self) -> ::std::option::Option<f64> {
        self.recall
    }
    /// <p>A measure of how accurate the recognizer results are for the test data. It is derived from the <code>Precision</code> and <code>Recall</code> values. The <code>F1Score</code> is the harmonic average of the two scores. For plain text entity recognizer models, the range is 0 to 100, where 100 is the best score. For PDF/Word entity recognizer models, the range is 0 to 1, where 1 is the best score.</p>
    pub fn f1_score(&self) -> ::std::option::Option<f64> {
        self.f1_score
    }
}
impl EntityRecognizerEvaluationMetrics {
    /// Creates a new builder-style object to manufacture [`EntityRecognizerEvaluationMetrics`](crate::types::EntityRecognizerEvaluationMetrics).
    pub fn builder() -> crate::types::builders::EntityRecognizerEvaluationMetricsBuilder {
        crate::types::builders::EntityRecognizerEvaluationMetricsBuilder::default()
    }
}

/// A builder for [`EntityRecognizerEvaluationMetrics`](crate::types::EntityRecognizerEvaluationMetrics).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct EntityRecognizerEvaluationMetricsBuilder {
    pub(crate) precision: ::std::option::Option<f64>,
    pub(crate) recall: ::std::option::Option<f64>,
    pub(crate) f1_score: ::std::option::Option<f64>,
}
impl EntityRecognizerEvaluationMetricsBuilder {
    /// <p>A measure of the usefulness of the recognizer results in the test data. High precision means that the recognizer returned substantially more relevant results than irrelevant ones.</p>
    pub fn precision(mut self, input: f64) -> Self {
        self.precision = ::std::option::Option::Some(input);
        self
    }
    /// <p>A measure of the usefulness of the recognizer results in the test data. High precision means that the recognizer returned substantially more relevant results than irrelevant ones.</p>
    pub fn set_precision(mut self, input: ::std::option::Option<f64>) -> Self {
        self.precision = input;
        self
    }
    /// <p>A measure of the usefulness of the recognizer results in the test data. High precision means that the recognizer returned substantially more relevant results than irrelevant ones.</p>
    pub fn get_precision(&self) -> &::std::option::Option<f64> {
        &self.precision
    }
    /// <p>A measure of how complete the recognizer results are for the test data. High recall means that the recognizer returned most of the relevant results.</p>
    pub fn recall(mut self, input: f64) -> Self {
        self.recall = ::std::option::Option::Some(input);
        self
    }
    /// <p>A measure of how complete the recognizer results are for the test data. High recall means that the recognizer returned most of the relevant results.</p>
    pub fn set_recall(mut self, input: ::std::option::Option<f64>) -> Self {
        self.recall = input;
        self
    }
    /// <p>A measure of how complete the recognizer results are for the test data. High recall means that the recognizer returned most of the relevant results.</p>
    pub fn get_recall(&self) -> &::std::option::Option<f64> {
        &self.recall
    }
    /// <p>A measure of how accurate the recognizer results are for the test data. It is derived from the <code>Precision</code> and <code>Recall</code> values. The <code>F1Score</code> is the harmonic average of the two scores. For plain text entity recognizer models, the range is 0 to 100, where 100 is the best score. For PDF/Word entity recognizer models, the range is 0 to 1, where 1 is the best score.</p>
    pub fn f1_score(mut self, input: f64) -> Self {
        self.f1_score = ::std::option::Option::Some(input);
        self
    }
    /// <p>A measure of how accurate the recognizer results are for the test data. It is derived from the <code>Precision</code> and <code>Recall</code> values. The <code>F1Score</code> is the harmonic average of the two scores. For plain text entity recognizer models, the range is 0 to 100, where 100 is the best score. For PDF/Word entity recognizer models, the range is 0 to 1, where 1 is the best score.</p>
    pub fn set_f1_score(mut self, input: ::std::option::Option<f64>) -> Self {
        self.f1_score = input;
        self
    }
    /// <p>A measure of how accurate the recognizer results are for the test data. It is derived from the <code>Precision</code> and <code>Recall</code> values. The <code>F1Score</code> is the harmonic average of the two scores. For plain text entity recognizer models, the range is 0 to 100, where 100 is the best score. For PDF/Word entity recognizer models, the range is 0 to 1, where 1 is the best score.</p>
    pub fn get_f1_score(&self) -> &::std::option::Option<f64> {
        &self.f1_score
    }
    /// Consumes the builder and constructs a [`EntityRecognizerEvaluationMetrics`](crate::types::EntityRecognizerEvaluationMetrics).
    pub fn build(self) -> crate::types::EntityRecognizerEvaluationMetrics {
        crate::types::EntityRecognizerEvaluationMetrics {
            precision: self.precision,
            recall: self.recall,
            f1_score: self.f1_score,
        }
    }
}
