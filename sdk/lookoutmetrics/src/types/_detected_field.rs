// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>An inferred field.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DetectedField {
    /// <p>The field's value.</p>
    pub value: ::std::option::Option<crate::types::AttributeValue>,
    /// <p>The field's confidence.</p>
    pub confidence: ::std::option::Option<crate::types::Confidence>,
    /// <p>The field's message.</p>
    pub message: ::std::option::Option<::std::string::String>,
}
impl DetectedField {
    /// <p>The field's value.</p>
    pub fn value(&self) -> ::std::option::Option<&crate::types::AttributeValue> {
        self.value.as_ref()
    }
    /// <p>The field's confidence.</p>
    pub fn confidence(&self) -> ::std::option::Option<&crate::types::Confidence> {
        self.confidence.as_ref()
    }
    /// <p>The field's message.</p>
    pub fn message(&self) -> ::std::option::Option<&str> {
        self.message.as_deref()
    }
}
impl DetectedField {
    /// Creates a new builder-style object to manufacture [`DetectedField`](crate::types::DetectedField).
    pub fn builder() -> crate::types::builders::DetectedFieldBuilder {
        crate::types::builders::DetectedFieldBuilder::default()
    }
}

/// A builder for [`DetectedField`](crate::types::DetectedField).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DetectedFieldBuilder {
    pub(crate) value: ::std::option::Option<crate::types::AttributeValue>,
    pub(crate) confidence: ::std::option::Option<crate::types::Confidence>,
    pub(crate) message: ::std::option::Option<::std::string::String>,
}
impl DetectedFieldBuilder {
    /// <p>The field's value.</p>
    pub fn value(mut self, input: crate::types::AttributeValue) -> Self {
        self.value = ::std::option::Option::Some(input);
        self
    }
    /// <p>The field's value.</p>
    pub fn set_value(mut self, input: ::std::option::Option<crate::types::AttributeValue>) -> Self {
        self.value = input;
        self
    }
    /// <p>The field's value.</p>
    pub fn get_value(&self) -> &::std::option::Option<crate::types::AttributeValue> {
        &self.value
    }
    /// <p>The field's confidence.</p>
    pub fn confidence(mut self, input: crate::types::Confidence) -> Self {
        self.confidence = ::std::option::Option::Some(input);
        self
    }
    /// <p>The field's confidence.</p>
    pub fn set_confidence(mut self, input: ::std::option::Option<crate::types::Confidence>) -> Self {
        self.confidence = input;
        self
    }
    /// <p>The field's confidence.</p>
    pub fn get_confidence(&self) -> &::std::option::Option<crate::types::Confidence> {
        &self.confidence
    }
    /// <p>The field's message.</p>
    pub fn message(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.message = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The field's message.</p>
    pub fn set_message(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.message = input;
        self
    }
    /// <p>The field's message.</p>
    pub fn get_message(&self) -> &::std::option::Option<::std::string::String> {
        &self.message
    }
    /// Consumes the builder and constructs a [`DetectedField`](crate::types::DetectedField).
    pub fn build(self) -> crate::types::DetectedField {
        crate::types::DetectedField {
            value: self.value,
            confidence: self.confidence,
            message: self.message,
        }
    }
}
