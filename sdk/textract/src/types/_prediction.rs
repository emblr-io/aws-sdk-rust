// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Contains information regarding predicted values returned by Amazon Textract operations, including the predicted value and the confidence in the predicted value.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct Prediction {
    /// <p>The predicted value of a detected object.</p>
    pub value: ::std::option::Option<::std::string::String>,
    /// <p>Amazon Textract's confidence in its predicted value.</p>
    pub confidence: ::std::option::Option<f32>,
}
impl Prediction {
    /// <p>The predicted value of a detected object.</p>
    pub fn value(&self) -> ::std::option::Option<&str> {
        self.value.as_deref()
    }
    /// <p>Amazon Textract's confidence in its predicted value.</p>
    pub fn confidence(&self) -> ::std::option::Option<f32> {
        self.confidence
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
    pub(crate) value: ::std::option::Option<::std::string::String>,
    pub(crate) confidence: ::std::option::Option<f32>,
}
impl PredictionBuilder {
    /// <p>The predicted value of a detected object.</p>
    pub fn value(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.value = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The predicted value of a detected object.</p>
    pub fn set_value(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.value = input;
        self
    }
    /// <p>The predicted value of a detected object.</p>
    pub fn get_value(&self) -> &::std::option::Option<::std::string::String> {
        &self.value
    }
    /// <p>Amazon Textract's confidence in its predicted value.</p>
    pub fn confidence(mut self, input: f32) -> Self {
        self.confidence = ::std::option::Option::Some(input);
        self
    }
    /// <p>Amazon Textract's confidence in its predicted value.</p>
    pub fn set_confidence(mut self, input: ::std::option::Option<f32>) -> Self {
        self.confidence = input;
        self
    }
    /// <p>Amazon Textract's confidence in its predicted value.</p>
    pub fn get_confidence(&self) -> &::std::option::Option<f32> {
        &self.confidence
    }
    /// Consumes the builder and constructs a [`Prediction`](crate::types::Prediction).
    pub fn build(self) -> crate::types::Prediction {
        crate::types::Prediction {
            value: self.value,
            confidence: self.confidence,
        }
    }
}
