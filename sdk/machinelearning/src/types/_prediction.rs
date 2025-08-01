// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The output from a <code>Predict</code> operation:</p>
/// <ul>
/// <li>
/// <p><code>Details</code> - Contains the following attributes: <code>DetailsAttributes.PREDICTIVE_MODEL_TYPE - REGRESSION | BINARY | MULTICLASS</code> <code>DetailsAttributes.ALGORITHM - SGD</code></p></li>
/// <li>
/// <p><code>PredictedLabel</code> - Present for either a <code>BINARY</code> or <code>MULTICLASS</code> <code>MLModel</code> request.</p></li>
/// <li>
/// <p><code>PredictedScores</code> - Contains the raw classification score corresponding to each label.</p></li>
/// <li>
/// <p><code>PredictedValue</code> - Present for a <code>REGRESSION</code> <code>MLModel</code> request.</p></li>
/// </ul>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct Prediction {
    /// <p>The prediction label for either a <code>BINARY</code> or <code>MULTICLASS</code> <code>MLModel</code>.</p>
    pub predicted_label: ::std::option::Option<::std::string::String>,
    /// <p>The prediction value for <code>REGRESSION</code> <code>MLModel</code>.</p>
    pub predicted_value: ::std::option::Option<f32>,
    /// <p>Provides the raw classification score corresponding to each label.</p>
    pub predicted_scores: ::std::option::Option<::std::collections::HashMap<::std::string::String, f32>>,
    /// <p>Provides any additional details regarding the prediction.</p>
    pub details: ::std::option::Option<::std::collections::HashMap<crate::types::DetailsAttributes, ::std::string::String>>,
}
impl Prediction {
    /// <p>The prediction label for either a <code>BINARY</code> or <code>MULTICLASS</code> <code>MLModel</code>.</p>
    pub fn predicted_label(&self) -> ::std::option::Option<&str> {
        self.predicted_label.as_deref()
    }
    /// <p>The prediction value for <code>REGRESSION</code> <code>MLModel</code>.</p>
    pub fn predicted_value(&self) -> ::std::option::Option<f32> {
        self.predicted_value
    }
    /// <p>Provides the raw classification score corresponding to each label.</p>
    pub fn predicted_scores(&self) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, f32>> {
        self.predicted_scores.as_ref()
    }
    /// <p>Provides any additional details regarding the prediction.</p>
    pub fn details(&self) -> ::std::option::Option<&::std::collections::HashMap<crate::types::DetailsAttributes, ::std::string::String>> {
        self.details.as_ref()
    }
}
impl Prediction {
    /// Creates a new builder-style object to manufacture [`Prediction`](crate::types::Prediction).
    pub fn builder() -> crate::types::builders::PredictionBuilder {
        crate::types::builders::PredictionBuilder::default()
    }
}

/// A builder for [`Prediction`](crate::types::Prediction).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct PredictionBuilder {
    pub(crate) predicted_label: ::std::option::Option<::std::string::String>,
    pub(crate) predicted_value: ::std::option::Option<f32>,
    pub(crate) predicted_scores: ::std::option::Option<::std::collections::HashMap<::std::string::String, f32>>,
    pub(crate) details: ::std::option::Option<::std::collections::HashMap<crate::types::DetailsAttributes, ::std::string::String>>,
}
impl PredictionBuilder {
    /// <p>The prediction label for either a <code>BINARY</code> or <code>MULTICLASS</code> <code>MLModel</code>.</p>
    pub fn predicted_label(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.predicted_label = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The prediction label for either a <code>BINARY</code> or <code>MULTICLASS</code> <code>MLModel</code>.</p>
    pub fn set_predicted_label(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.predicted_label = input;
        self
    }
    /// <p>The prediction label for either a <code>BINARY</code> or <code>MULTICLASS</code> <code>MLModel</code>.</p>
    pub fn get_predicted_label(&self) -> &::std::option::Option<::std::string::String> {
        &self.predicted_label
    }
    /// <p>The prediction value for <code>REGRESSION</code> <code>MLModel</code>.</p>
    pub fn predicted_value(mut self, input: f32) -> Self {
        self.predicted_value = ::std::option::Option::Some(input);
        self
    }
    /// <p>The prediction value for <code>REGRESSION</code> <code>MLModel</code>.</p>
    pub fn set_predicted_value(mut self, input: ::std::option::Option<f32>) -> Self {
        self.predicted_value = input;
        self
    }
    /// <p>The prediction value for <code>REGRESSION</code> <code>MLModel</code>.</p>
    pub fn get_predicted_value(&self) -> &::std::option::Option<f32> {
        &self.predicted_value
    }
    /// Adds a key-value pair to `predicted_scores`.
    ///
    /// To override the contents of this collection use [`set_predicted_scores`](Self::set_predicted_scores).
    ///
    /// <p>Provides the raw classification score corresponding to each label.</p>
    pub fn predicted_scores(mut self, k: impl ::std::convert::Into<::std::string::String>, v: f32) -> Self {
        let mut hash_map = self.predicted_scores.unwrap_or_default();
        hash_map.insert(k.into(), v);
        self.predicted_scores = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>Provides the raw classification score corresponding to each label.</p>
    pub fn set_predicted_scores(mut self, input: ::std::option::Option<::std::collections::HashMap<::std::string::String, f32>>) -> Self {
        self.predicted_scores = input;
        self
    }
    /// <p>Provides the raw classification score corresponding to each label.</p>
    pub fn get_predicted_scores(&self) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, f32>> {
        &self.predicted_scores
    }
    /// Adds a key-value pair to `details`.
    ///
    /// To override the contents of this collection use [`set_details`](Self::set_details).
    ///
    /// <p>Provides any additional details regarding the prediction.</p>
    pub fn details(mut self, k: crate::types::DetailsAttributes, v: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut hash_map = self.details.unwrap_or_default();
        hash_map.insert(k, v.into());
        self.details = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>Provides any additional details regarding the prediction.</p>
    pub fn set_details(
        mut self,
        input: ::std::option::Option<::std::collections::HashMap<crate::types::DetailsAttributes, ::std::string::String>>,
    ) -> Self {
        self.details = input;
        self
    }
    /// <p>Provides any additional details regarding the prediction.</p>
    pub fn get_details(&self) -> &::std::option::Option<::std::collections::HashMap<crate::types::DetailsAttributes, ::std::string::String>> {
        &self.details
    }
    /// Consumes the builder and constructs a [`Prediction`](crate::types::Prediction).
    pub fn build(self) -> crate::types::Prediction {
        crate::types::Prediction {
            predicted_label: self.predicted_label,
            predicted_value: self.predicted_value,
            predicted_scores: self.predicted_scores,
            details: self.details,
        }
    }
}
