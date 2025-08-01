// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Provides information about a type of sensitive data that was detected by a managed data identifier and produced a sensitive data finding.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DefaultDetection {
    /// <p>The total number of occurrences of the type of sensitive data that was detected.</p>
    pub count: ::std::option::Option<i64>,
    /// <p>The location of 1-15 occurrences of the sensitive data that was detected. A finding includes location data for a maximum of 15 occurrences of sensitive data.</p>
    pub occurrences: ::std::option::Option<crate::types::Occurrences>,
    /// <p>The type of sensitive data that was detected. For example, AWS_CREDENTIALS, PHONE_NUMBER, or ADDRESS.</p>
    pub r#type: ::std::option::Option<::std::string::String>,
}
impl DefaultDetection {
    /// <p>The total number of occurrences of the type of sensitive data that was detected.</p>
    pub fn count(&self) -> ::std::option::Option<i64> {
        self.count
    }
    /// <p>The location of 1-15 occurrences of the sensitive data that was detected. A finding includes location data for a maximum of 15 occurrences of sensitive data.</p>
    pub fn occurrences(&self) -> ::std::option::Option<&crate::types::Occurrences> {
        self.occurrences.as_ref()
    }
    /// <p>The type of sensitive data that was detected. For example, AWS_CREDENTIALS, PHONE_NUMBER, or ADDRESS.</p>
    pub fn r#type(&self) -> ::std::option::Option<&str> {
        self.r#type.as_deref()
    }
}
impl DefaultDetection {
    /// Creates a new builder-style object to manufacture [`DefaultDetection`](crate::types::DefaultDetection).
    pub fn builder() -> crate::types::builders::DefaultDetectionBuilder {
        crate::types::builders::DefaultDetectionBuilder::default()
    }
}

/// A builder for [`DefaultDetection`](crate::types::DefaultDetection).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DefaultDetectionBuilder {
    pub(crate) count: ::std::option::Option<i64>,
    pub(crate) occurrences: ::std::option::Option<crate::types::Occurrences>,
    pub(crate) r#type: ::std::option::Option<::std::string::String>,
}
impl DefaultDetectionBuilder {
    /// <p>The total number of occurrences of the type of sensitive data that was detected.</p>
    pub fn count(mut self, input: i64) -> Self {
        self.count = ::std::option::Option::Some(input);
        self
    }
    /// <p>The total number of occurrences of the type of sensitive data that was detected.</p>
    pub fn set_count(mut self, input: ::std::option::Option<i64>) -> Self {
        self.count = input;
        self
    }
    /// <p>The total number of occurrences of the type of sensitive data that was detected.</p>
    pub fn get_count(&self) -> &::std::option::Option<i64> {
        &self.count
    }
    /// <p>The location of 1-15 occurrences of the sensitive data that was detected. A finding includes location data for a maximum of 15 occurrences of sensitive data.</p>
    pub fn occurrences(mut self, input: crate::types::Occurrences) -> Self {
        self.occurrences = ::std::option::Option::Some(input);
        self
    }
    /// <p>The location of 1-15 occurrences of the sensitive data that was detected. A finding includes location data for a maximum of 15 occurrences of sensitive data.</p>
    pub fn set_occurrences(mut self, input: ::std::option::Option<crate::types::Occurrences>) -> Self {
        self.occurrences = input;
        self
    }
    /// <p>The location of 1-15 occurrences of the sensitive data that was detected. A finding includes location data for a maximum of 15 occurrences of sensitive data.</p>
    pub fn get_occurrences(&self) -> &::std::option::Option<crate::types::Occurrences> {
        &self.occurrences
    }
    /// <p>The type of sensitive data that was detected. For example, AWS_CREDENTIALS, PHONE_NUMBER, or ADDRESS.</p>
    pub fn r#type(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.r#type = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The type of sensitive data that was detected. For example, AWS_CREDENTIALS, PHONE_NUMBER, or ADDRESS.</p>
    pub fn set_type(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.r#type = input;
        self
    }
    /// <p>The type of sensitive data that was detected. For example, AWS_CREDENTIALS, PHONE_NUMBER, or ADDRESS.</p>
    pub fn get_type(&self) -> &::std::option::Option<::std::string::String> {
        &self.r#type
    }
    /// Consumes the builder and constructs a [`DefaultDetection`](crate::types::DefaultDetection).
    pub fn build(self) -> crate::types::DefaultDetection {
        crate::types::DefaultDetection {
            count: self.count,
            occurrences: self.occurrences,
            r#type: self.r#type,
        }
    }
}
